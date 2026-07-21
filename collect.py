#!/usr/bin/env python3
"""
Network Snapshot — collector
============================

Runs on a laptop plugged into a prospect's network. Orchestrates a handful of
standard tools, then emits ONE structured JSON file (the "snapshot") describing
what it found — hosts, open ports/services, LLDP/VLAN topology, and nearby WiFi.

The snapshot JSON is the whole contract. Everything downstream (categorization,
the AI narrative, the report) consumes this file and nothing else, so the report
side can live in a host app today and move elsewhere later without touching this.

Design notes
------------
* Dependency-light on purpose: shells out to system tools and parses their
  output with the stdlib. No `pip install` beyond Python 3.9+.
* Every collection step is isolated — a missing tool or a failing step degrades
  gracefully and is recorded, it never aborts the scan.
* `active` (default) sends probes (arp-scan + nmap). `--passive` only listens
  (LLDP + mDNS + a sniff for ARP/DHCP) plus a WiFi scan — for sensitive sites
  or when an incumbent MSP is watching.

Tools used (install on the laptop): nmap, arp-scan, tcpdump, avahi-utils
(avahi-browse), and NetworkManager (nmcli) or iw for WiFi. Run with sudo.

    sudo python3 collect.py --site "Acme Dental" -o acme.json
    sudo python3 collect.py --passive --site "Acme Dental"
    python3 collect.py --demo -o sample-snapshot.json   # no network needed
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

COLLECTOR_VERSION = "0.4.1"
SCHEMA_VERSION = "1.0"

# GitHub is the source of truth — every run checks for a newer version first.
REPO_SLUG = "tes5884/network-snapshot"
REPO_RAW_URL = f"https://raw.githubusercontent.com/{REPO_SLUG}/main/collect.py"
REPO_WEB_URL = f"https://github.com/{REPO_SLUG}"

# Curated "fingerprint" ports — enough to identify device roles without the
# noise/time of a full 65k sweep. RTSP=camera, 9100=printer, 3389=RDP, etc.
FINGERPRINT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,161,443,445,515,554,587,631,"
    "993,995,1433,1521,1723,1883,2049,3128,3306,3389,5000,5060,5432,5900,"
    "5984,6379,8000,8080,8443,8888,9100,9200,11211,27017,32400,49152"
)
# NSE scripts that reveal roles/risks without being aggressive. smb-protocols/
# smb2-security-mode → SMBv1 + signing; redis/mongodb-info return data only when
# the service is UNAUTHENTICATED (that's the finding).
NSE_SCRIPTS = ("smb-os-discovery,smb-enum-shares,smb-protocols,smb2-security-mode,"
               "snmp-info,http-title,ssl-cert,redis-info,mongodb-info")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[snapshot] {msg}", file=sys.stderr, flush=True)


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a command, capturing output. Never raises — returns rc/-1 on error."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return -1, "", "not found"
    except subprocess.TimeoutExpired as e:
        return -1, e.stdout or "", "timeout"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


# ── Tool preflight ───────────────────────────────────────────────────────────
# (binary, apt package, what it's for, required?)
TOOLS = [
    ("ip", "iproute2", "interface & route detection", True),
    ("nmap", "nmap", "host / service / OS discovery", True),
    ("arp-scan", "arp-scan", "fast layer-2 host + MAC sweep", True),
    ("tcpdump", "tcpdump", "LLDP capture + passive sniff", True),
    ("avahi-browse", "avahi-utils", "mDNS service discovery", False),
    ("lldpctl", "lldpd", "LLDP neighbor table (switch / VLAN)", False),
    ("snmpwalk", "snmp", "SNMP topology (switch links, router id)", False),
    ("nmcli", "network-manager", "WiFi scan (managed mode)", False),
    ("iw", "iw", "WiFi info / monitor-mode fallback", False),
    ("airodump-ng", "aircrack-ng", "monitor-mode WiFi survey", False),
    ("dig", "dnsutils", "reverse DNS + zone-transfer (AXFR)", False),
    ("nbtscan", "nbtscan", "NetBIOS names + workgroup/domain", False),
    ("onesixtyone", "onesixtyone", "SNMP host + community discovery", False),
    ("speedtest-cli", "speedtest-cli", "WAN bandwidth (opt-in --speedtest)", False),
    ("traceroute", "traceroute", "circuit path + double-NAT detection", False),
    ("rdisc6", "ndisc6", "IPv6 rogue Router-Advertisement check", False),
]


def doctor(assume_yes: bool = False) -> bool:
    """Report which tools are present, offer to apt-install the missing ones.
    Returns True if it's OK to proceed (all *required* tools available)."""
    missing = [(b, pkg, why, req) for (b, pkg, why, req) in TOOLS if not have(b)]
    print("Tool check:", file=sys.stderr)
    for (b, pkg, why, req) in TOOLS:
        mark = "✓" if have(b) else ("✗ REQUIRED" if req else "○ optional")
        print(f"  {mark:12} {b:14} — {why}", file=sys.stderr)
    if not missing:
        print("All tools present.\n", file=sys.stderr)
        return True

    pkgs = sorted({pkg for (_, pkg, _, _) in missing})
    req_missing = [b for (b, _, _, r) in missing if r]
    if not have("apt-get"):
        print(f"\nMissing: {', '.join(b for b,_,_,_ in missing)}. Install manually "
              f"(this isn't an apt system): {' '.join(pkgs)}\n", file=sys.stderr)
        return not req_missing

    cmd = (["sudo"] if hasattr(os, "geteuid") and os.geteuid() != 0 else []) + ["apt-get", "install", "-y"] + pkgs
    print(f"\nMissing {len(missing)} tool(s). Install with:\n  {shlex.join(cmd)}", file=sys.stderr)
    do = assume_yes
    if not assume_yes:
        try:
            do = input("Install now? [Y/n] ").strip().lower() in ("", "y", "yes")
        except EOFError:
            do = False
    if do:
        run_i = subprocess.run(["sudo", "apt-get", "update"] if os.geteuid() != 0 else ["apt-get", "update"])
        subprocess.run(cmd)
        still = [b for (b, _, _, r) in missing if not have(b) and r]
        if still:
            print(f"\nStill missing required: {', '.join(still)} — scan will be limited.\n", file=sys.stderr)
        else:
            print("Install complete.\n", file=sys.stderr)
            return True
    if req_missing:
        print(f"\n⚠ Proceeding without required tool(s) {', '.join(req_missing)} — "
              "the snapshot will be thin.\n", file=sys.stderr)
    return True


# ── Interface / local network ────────────────────────────────────────────────

def detect_interface(prefer: str | None) -> dict:
    """Primary interface + IPv4/CIDR/gateway. Uses `ip` (Linux) with a macOS
    fallback via `route`/`ifconfig`."""
    info: dict = {"name": prefer, "mac": None, "ipv4": None, "cidr": None, "gateway": None}

    # Default route → interface + gateway
    rc, out, _ = run(["ip", "route", "show", "default"], 5)
    if rc == 0 and out:
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            info["gateway"] = m.group(1)
            info["name"] = info["name"] or m.group(2)
    if not info["name"]:
        # macOS fallback
        rc, out, _ = run(["route", "-n", "get", "default"], 5)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                info["name"] = line.split()[-1]
            if line.startswith("gateway:"):
                info["gateway"] = line.split()[-1]

    iface = info["name"]
    if not iface:
        return info

    # IP + CIDR for that interface
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show", "dev", iface], 5)
    if rc == 0 and out:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            info["ipv4"] = m.group(1)
            info["cidr"] = str(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
    rc, out, _ = run(["cat", f"/sys/class/net/{iface}/address"], 5)
    if rc == 0 and out.strip():
        info["mac"] = out.strip()
    return info


# ── Active: arp-scan (fast L2 host + MAC + vendor) ───────────────────────────

def run_arp_scan(iface: str) -> tuple[dict[str, dict], list[dict]]:
    """Returns (hosts, duplicate_ips). A duplicate = one IP answering from two
    different MACs — a real IP conflict (intermittent connectivity for both)."""
    hosts: dict[str, dict] = {}
    macs_by_ip: dict[str, set] = {}
    if not have("arp-scan"):
        return hosts, []
    rc, out, _ = run(["arp-scan", "--interface", iface, "--localnet", "--retry=2"], 120)
    for line in out.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$", line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            vendor = re.sub(r"\s*\(DUP:\s*\d+\)", "", m.group(3)).strip()
            macs_by_ip.setdefault(ip, set()).add(mac)
            hosts[ip] = {"mac": mac, "vendor": vendor or None, "discovered_by": ["arp"]}
    duplicates = [{"ip": ip, "macs": sorted(ms)} for ip, ms in macs_by_ip.items() if len(ms) > 1]
    return hosts, duplicates


# ── Active: nmap (services, OS, SMB shares, SNMP) ────────────────────────────

def run_nmap(target: str, timeout: int) -> dict[str, dict]:
    hosts: dict[str, dict] = {}
    if not have("nmap"):
        return hosts
    cmd = [
        "nmap", "-sS", "-sV", "-O", "--osscan-limit", "-T4",
        "--host-timeout", "90s", "-p", FINGERPRINT_PORTS,
        "--script", NSE_SCRIPTS, "-oX", "-", target,
    ]
    rc, out, _ = run(cmd, timeout)
    if not out:
        return hosts
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        addr = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        ip = addr.get("ipv4")
        if not ip:
            continue
        rec: dict = {"discovered_by": ["nmap"]}
        if "mac" in addr:
            rec["mac"] = addr["mac"].lower()
            vend = next((a.get("vendor") for a in h.findall("address") if a.get("addrtype") == "mac" and a.get("vendor")), None)
            if vend:
                rec["vendor"] = vend
        # hostname
        hn = h.find("hostnames/hostname")
        if hn is not None and hn.get("name"):
            rec["hostname"] = hn.get("name")
        # os
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            rec["os_guess"] = {"name": osmatch.get("name"), "accuracy": int(osmatch.get("accuracy") or 0)}
        # ports
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            entry = {"port": int(p.get("portid")), "proto": p.get("protocol")}
            if svc is not None:
                for k_xml, k_out in (("name", "service"), ("product", "product"), ("version", "version")):
                    if svc.get(k_xml):
                        entry[k_out] = svc.get(k_xml)
            # http title / ssl cert from NSE; redis/mongo info = unauthenticated
            for scr in p.findall("script"):
                if scr.get("id") == "http-title" and scr.get("output"):
                    entry["title"] = scr.get("output").strip()
                elif scr.get("id") in ("redis-info", "mongodb-info") and scr.get("output"):
                    entry["unauth"] = True   # the info script only succeeds without auth
            ports.append(entry)
        if ports:
            rec["open_ports"] = ports
        # host-level NSE: SMB shares/OS, SNMP
        for scr in h.findall("hostscript/script"):
            sid, sout = scr.get("id"), (scr.get("output") or "").strip()
            if sid == "smb-enum-shares" and sout:
                shares = []
                for block in re.split(r"\n\s*\n", sout):
                    nm = re.search(r"^\s*([^\n:]+):\s*$", block, re.M) or re.search(r"Sharename:\s*(\S+)", block)
                    anon = "Anonymous access:" in block and re.search(r"Anonymous access:\s*(READ|WRITE)", block)
                    if nm:
                        shares.append({
                            "name": nm.group(1).strip(),
                            "anonymous": bool(anon),
                            "access": (anon.group(1) if anon else None),
                        })
                rec.setdefault("smb", {})["shares"] = shares
            elif sid == "smb-os-discovery" and sout:
                rec.setdefault("smb", {})["os"] = sout.splitlines()[0].strip()
            elif sid == "snmp-info" and sout:
                rec.setdefault("snmp", {})["sysdescr"] = sout.splitlines()[0].strip()
                rec["snmp"]["reachable"] = True
            elif sid == "smb-protocols" and sout:
                if re.search(r"SMBv1|NT LM 0\.12", sout):
                    rec.setdefault("smb", {})["smbv1"] = True
            elif sid == "smb2-security-mode" and sout:
                low = sout.lower()
                rec.setdefault("smb", {})["signing"] = (
                    "disabled" if "disabled" in low
                    else "not_required" if "not required" in low
                    else "required" if "required" in low else "unknown")
        hosts[ip] = rec
    return hosts


# ── Passive: LLDP/CDP (switch, port, VLAN) ───────────────────────────────────

def capture_lldp(iface: str, seconds: int) -> list[dict]:
    """Prefer lldpctl (if lldpd is running); else sniff LLDP frames with tcpdump."""
    neighbors: list[dict] = []
    if have("lldpctl"):
        rc, out, _ = run(["lldpctl", "-f", "json"], seconds + 5)
        if rc == 0 and out:
            try:
                data = json.loads(out)
                ifaces = data.get("lldp", {}).get("interface", {})
                for name, det in (ifaces.items() if isinstance(ifaces, dict) else []):
                    chassis = det.get("chassis", {})
                    port = det.get("port", {})
                    sw_name = next(iter(chassis)) if isinstance(chassis, dict) and chassis else None
                    chassis_det = chassis.get(sw_name, {}) if isinstance(chassis, dict) else {}
                    vlan = det.get("vlan", {})

                    def _val(x):
                        if isinstance(x, dict):
                            return x.get("value")
                        if isinstance(x, list) and x:
                            return x[0].get("value") if isinstance(x[0], dict) else x[0]
                        return x

                    neighbors.append({
                        "local_port": name,
                        "switch_name": sw_name,
                        "switch_port": (port.get("id", {}) or {}).get("value") if isinstance(port.get("id"), dict) else port.get("descr"),
                        "port_descr": _val(port.get("descr")),
                        "vlan": (vlan.get("vlan-id") if isinstance(vlan, dict) else None),
                        "mgmt_ip": _val(chassis_det.get("mgmt-ip")),
                        "poe": bool(port.get("power")),
                        "source": "lldpd",
                    })
            except (ValueError, AttributeError):
                pass
    if not neighbors and have("tcpdump"):
        # Raw LLDP (ethertype 0x88cc). Best-effort textual parse.
        rc, out, _ = run(
            ["tcpdump", "-i", iface, "-s", "0", "-c", "3", "-v", "ether", "proto", "0x88cc"],
            seconds + 5,
        )
        if out:
            sw = re.search(r"System Name.*?:\s*(\S+)", out)
            port = re.search(r"Port (?:Description|ID).*?:\s*(\S+)", out)
            vlan = re.search(r"VLAN ?(?:ID)?\s*[:#]?\s*(\d+)", out)
            if sw or port or vlan:
                neighbors.append({
                    "local_port": iface,
                    "switch_name": sw.group(1) if sw else None,
                    "switch_port": port.group(1) if port else None,
                    "vlan": int(vlan.group(1)) if vlan else None,
                    "source": "tcpdump",
                })
    return neighbors


def stp_probe(iface: str, seconds: int) -> dict:
    """Listen for spanning-tree BPDUs (the switch sends them ~every 2s; we only
    listen, emit nothing). Reveals STP vs RSTP vs MSTP, the root bridge, and
    whether the root is tuned — the spanning tree as seen from this jack."""
    if not have("tcpdump") or not iface:
        return {"present": False}
    _, out, _ = run(["tcpdump", "-i", iface, "-c", "4", "-e", "-v", "-nn", "stp"], min(seconds, 15) + 6)
    if not out or "STP" not in out:
        return {"present": False}
    version = ("rstp" if re.search(r"802\.1w|Rapid STP", out)
               else "mstp" if re.search(r"802\.1s|MSTP", out) else "stp")

    def bridge_id(label):
        m = re.search(label + r"\s+([0-9a-fA-F]{1,4})\.((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", out)
        return {"priority": int(m.group(1), 16), "mac": m.group(2).lower()} if m else None

    root, bridge = bridge_id("root-id"), bridge_id("bridge-id")
    cost = re.search(r"root-pathcost\s+(\d+)", out)
    return {
        "present": True,
        "version": version,
        "root": root,
        "designated_bridge": bridge,
        "root_pathcost": int(cost.group(1)) if cost else None,
        "is_root_here": bool(root and bridge and root["mac"] == bridge["mac"]),
    }


# ── Passive: mDNS service discovery ──────────────────────────────────────────

def browse_mdns(seconds: int) -> dict[str, list[str]]:
    """IP → list of announced service types (e.g. _ipp._tcp = printer)."""
    services: dict[str, list[str]] = {}
    if not have("avahi-browse"):
        return services
    rc, out, _ = run(["avahi-browse", "-a", "-r", "-p", "-t"], seconds + 5)
    # Resolved records ('=') carry the address + service type
    for line in out.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 8:
            continue
        svc_type, addr = parts[4], parts[7]
        if addr and re.match(r"\d+\.\d+\.\d+\.\d+", addr):
            services.setdefault(addr, [])
            if svc_type not in services[addr]:
                services[addr].append(svc_type)
    return services


# ── Passive: sniff ARP/DHCP to enumerate hosts without probing ───────────────

def passive_sniff(iface: str, seconds: int) -> dict[str, dict]:
    hosts: dict[str, dict] = {}
    if not have("tcpdump"):
        return hosts
    rc, out, _ = run(
        ["tcpdump", "-i", iface, "-n", "-l", "-e", "-c", "500",
         "arp or (udp port 67 or 68)"],
        seconds + 5,
    )
    for line in out.splitlines():
        # ARP: "... aa:bb:cc:dd:ee:ff > ... , Request who-has 10.0.0.5 tell 10.0.0.9"
        mac = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5}) >", line)
        for ip in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", line):
            if ip.endswith(".255") or ip == "0.0.0.0":
                continue
            rec = hosts.setdefault(ip, {"discovered_by": ["passive"]})
            if mac and "mac" not in rec:
                rec["mac"] = mac.group(1)
    return hosts


# ── SNMP topology (switches/router → who links where, what's on each port) ───
# The physical-diagram source. Walks standard MIBs by numeric OID (no MIB files
# needed): system identity, the LLDP remote-neighbor table (switch↔switch↔AP
# links), and interfaces. Tries community strings against the gateway + any
# SNMP-responsive gear. Read-only; all scans are done with customer consent.

_SNMP = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "lldp_rem_sysname": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldp_rem_portid": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldp_rem_portdesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_oper": "1.3.6.1.2.1.2.2.1.8",
}


def _snmp_role(descr: str) -> str:
    d = (descr or "").lower()
    if re.search(r"firewall|fortigate|sonicwall|palo alto|pfsense|edgerouter|mikrotik|\budm\b|\busg\b|router", d):
        return "router/firewall"
    if re.search(r"switch|catalyst|procurve|nexus|aruba|unifi.*switch", d):
        return "switch"
    if re.search(r"access point|\buap\b|wireless", d):
        return "access-point"
    return "snmp-device"


def parse_snmp_walk(text: str) -> list[tuple[str, str]]:
    """snmpwalk -Oqn output → [(numeric_oid, value)]. Pure/ testable."""
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln.startswith("."):
            continue
        oid, _, val = ln.partition(" ")
        val = val.strip().strip('"')
        if val and "No Such" not in val and val != "":
            out.append((oid, val))
    return out


def _snmp_walk(ip: str, community: str, base: str, timeout: int = 15) -> list[tuple[str, str]]:
    tool = "snmpbulkwalk" if have("snmpbulkwalk") else "snmpwalk"
    rc, out, _ = run([tool, "-v2c", "-c", community, "-Oqn", "-t", "2", "-r", "1", ip, base], timeout)
    return parse_snmp_walk(out) if out else []


def _suffix_map(rows: list[tuple[str, str]], base: str) -> dict[str, str]:
    """Map each row's OID index (the part after `base`) → value. Normalizes the
    leading dot snmpwalk emits so the slice lines up regardless."""
    m: dict[str, str] = {}
    for oid, v in rows:
        o = oid.lstrip(".")
        if o.startswith(base):
            m[o[len(base):]] = v
    return m


def _lldp_neighbors(ip: str, community: str) -> list[dict]:
    """Correlate the LLDP remote-table columns by their shared OID index →
    each neighbor's name + port as seen from this device."""
    names = _suffix_map(_snmp_walk(ip, community, _SNMP["lldp_rem_sysname"]), _SNMP["lldp_rem_sysname"])
    portids = _suffix_map(_snmp_walk(ip, community, _SNMP["lldp_rem_portid"]), _SNMP["lldp_rem_portid"])
    portdescs = _suffix_map(_snmp_walk(ip, community, _SNMP["lldp_rem_portdesc"]), _SNMP["lldp_rem_portdesc"])
    neighbors = []
    for idx, name in names.items():
        parts = idx.strip(".").split(".")
        local_port = parts[1] if len(parts) > 1 else None  # lldpRemLocalPortNum
        neighbors.append({
            "local_port": local_port,
            "neighbor_name": name,
            "neighbor_port": portdescs.get(idx) or portids.get(idx),
        })
    return neighbors


def snmp_topology(targets: list[str], communities: list[str]) -> dict:
    if not (have("snmpwalk") or have("snmpbulkwalk")):
        return {"devices": [], "edges": []}
    devices, edges = [], []
    for ip in targets[:20]:  # bound the sweep
        descr = name = None
        used = None
        for community in communities:
            rc, out, _ = run(["snmpget", "-v2c", "-c", community, "-Oqv", "-t", "2", "-r", "1", ip, _SNMP["sys_descr"]], 8)
            if rc == 0 and out.strip() and "No Such" not in out and "Timeout" not in out:
                descr = out.strip().strip('"')
                used = community
                break
        if not used:
            continue  # no SNMP here
        nm = _snmp_walk(ip, used, _SNMP["sys_name"])
        name = nm[0][1] if nm else None
        neighbors = _lldp_neighbors(ip, used)
        ifs = _snmp_walk(ip, used, _SNMP["if_name"])
        oper = dict(_snmp_walk(ip, used, _SNMP["if_oper"]))
        up = sum(1 for oid, v in oper.items() if v.strip() in ("1", "up"))
        devices.append({
            "ip": ip,
            "sysname": name,
            "sysdescr": descr,
            "role_guess": _snmp_role(descr),
            "neighbor_count": len(neighbors),
            "neighbors": neighbors,
            "interfaces": len(ifs),
            "interfaces_up": up,
            "community_used": used,
        })
        for nb in neighbors:
            edges.append({"from": name or ip, "from_port": nb["local_port"],
                          "to": nb["neighbor_name"], "to_port": nb["neighbor_port"]})
    return {"devices": devices, "edges": edges}


# ── DNS: reverse-resolve hosts + zone-transfer (AXFR) attempt ────────────────
# Reverse-DNS turns IPs into real hostnames. AXFR, if the DNS server allows it
# (common misconfig in SMBs), dumps the ENTIRE internal zone — every host, even
# ones that were quiet during the scan. Highest-leverage inventory source.

def _resolv_conf() -> tuple[list[str], list[str]]:
    servers, domains = [], []
    try:
        with open("/etc/resolv.conf") as f:
            for ln in f:
                p = ln.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    servers.append(p[1])
                elif len(p) >= 2 and p[0] in ("search", "domain"):
                    domains += p[1:]
    except OSError:
        pass
    return servers, domains


def parse_axfr(text: str) -> list[dict]:
    """dig +noall +answer AXFR output → records. Testable."""
    recs = []
    for ln in text.splitlines():
        p = ln.split()
        if len(p) >= 5 and p[2] == "IN":
            recs.append({"name": p[0].rstrip("."), "type": p[3], "value": " ".join(p[4:]).rstrip(".")})
    return recs


def dns_recon(hosts: list[dict], gateway: str | None, domain_hints: list[str]) -> dict:
    result = {"servers": [], "domains": [], "reverse": {}, "axfr": {}, "axfr_open": False}
    if not have("dig"):
        return result
    servers, domains = _resolv_conf()
    if gateway:
        servers.append(gateway)
    for h in hosts:
        if any(p.get("port") == 53 for p in h.get("open_ports", [])):
            servers.append(h["ipv4"])
    servers = list(dict.fromkeys(s for s in servers if s))
    domains = list(dict.fromkeys([*domains, *domain_hints]))
    result["servers"] = servers
    if not servers:
        return result
    primary = servers[0]

    def rev(h):
        rc, out, _ = run(["dig", "+short", "-x", h["ipv4"], "@" + primary], 5)
        nm = out.strip().splitlines()[0].rstrip(".") if out.strip() else None
        return h["ipv4"], (nm or None)

    with ThreadPoolExecutor(max_workers=10) as pool:
        for ip, nm in pool.map(rev, hosts):
            if nm:
                result["reverse"][ip] = nm
                host = next((x for x in hosts if x["ipv4"] == ip), None)
                if host:
                    host["dns_name"] = nm
                if "." in nm:
                    dom = nm.split(".", 1)[1]
                    if dom not in domains:
                        domains.append(dom)
    result["domains"] = domains

    for server in servers[:3]:
        for dom in domains[:5]:
            rc, out, _ = run(["dig", "+noall", "+answer", "-t", "AXFR", dom, "@" + server], 20)
            recs = parse_axfr(out)
            if len(recs) > 1:  # a real transfer returns the whole zone
                result["axfr"][f"{dom}@{server}"] = recs
                result["axfr_open"] = True
    return result


# ── NetBIOS: Windows names + workgroup/domain ────────────────────────────────

def parse_nbtscan(text: str) -> dict[str, str]:
    names = {}
    for ln in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([^\s<]+)", ln)
        if m and m.group(2) not in ("Name", "-", "Sendto"):
            names.setdefault(m.group(1), m.group(2).strip("\\"))
    return names


def netbios_scan(cidr: str) -> dict[str, str]:
    if not have("nbtscan") or not cidr:
        return {}
    rc, out, _ = run(["nbtscan", cidr], 60)
    return parse_nbtscan(out)


# ── SNMP discovery (onesixtyone) — find every SNMP host + working community ──

def parse_onesixtyone(text: str) -> dict[str, dict]:
    found = {}
    for ln in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\[([^\]]+)\]\s*(.*)$", ln)
        if m:
            found[m.group(1)] = {"community": m.group(2), "sysdescr": m.group(3).strip()}
    return found


def snmp_discover(cidr: str, communities: list[str]) -> dict[str, dict]:
    if not have("onesixtyone") or not cidr:
        return {}
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(communities) + "\n")
        path = f.name
    try:
        rc, out, _ = run(["onesixtyone", "-c", path, cidr], 90)
        return parse_onesixtyone(out)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ── WAN speed test (opt-in — saturates the circuit for ~30s) ─────────────────

def speed_test() -> dict | None:
    tool = "speedtest-cli" if have("speedtest-cli") else ("speedtest" if have("speedtest") else None)
    if not tool:
        return None
    args_ = ["--json"] if tool == "speedtest-cli" else ["--format=json", "--accept-license", "--accept-gdpr"]
    rc, out, _ = run([tool] + args_, 120)
    try:
        d = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except (ValueError, IndexError):
        return None
    if tool == "speedtest-cli":
        res = {"download_mbps": round(d.get("download", 0) / 1e6, 1),
               "upload_mbps": round(d.get("upload", 0) / 1e6, 1),
               "ping_ms": round(d.get("ping", 0), 1),
               "isp": (d.get("client") or {}).get("isp"),
               "public_ip": (d.get("client") or {}).get("ip"),
               "server": (d.get("server") or {}).get("sponsor")}
    else:
        res = {"download_mbps": round(d.get("download", {}).get("bandwidth", 0) * 8 / 1e6, 1),
               "upload_mbps": round(d.get("upload", {}).get("bandwidth", 0) * 8 / 1e6, 1),
               "ping_ms": round(d.get("ping", {}).get("latency", 0), 1),
               "isp": d.get("isp"),
               "public_ip": (d.get("interface") or {}).get("externalIp"),
               "server": (d.get("server") or {}).get("name")}
    # A 0 download is a failed measurement, not a real result — report it as a
    # failed step so the WAN block stays clean (public_ip() still fills the IP).
    return res if res["download_mbps"] else None


def public_ip() -> dict | None:
    """The site's public/WAN IP — cheap, always useful (remote access, DNS,
    firewall scoping), and unlike the speed test it doesn't touch the circuit.
    One outbound HTTPS request to an IP-echo service; degrades to None offline.
    ipinfo also returns the ISP/org and rough geo for free."""
    for url in ("https://ipinfo.io/json", "https://api.ipify.org?format=json"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "network-snapshot"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                d = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 — offline / blocked / rate-limited
            continue
        ip = d.get("ip")
        if not ip:
            continue
        out = {"public_ip": ip}
        if d.get("org"):
            out["isp"] = d["org"]
        geo = ", ".join(x for x in (d.get("city"), d.get("region")) if x)
        if geo:
            out["geo"] = geo
        return out
    return None


# ── WiFi scan ────────────────────────────────────────────────────────────────

def scan_wifi() -> list[dict]:
    aps: list[dict] = []
    if have("nmcli"):
        rc, out, _ = run(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SECURITY,SIGNAL,FREQ", "dev", "wifi", "list", "--rescan", "yes"],
            30,
        )
        seen = set()
        for line in out.splitlines():
            # nmcli terse mode delimits with ':' but escapes literal ':' inside a
            # field (e.g. the BSSID MAC) as '\:'. Split on unescaped colons, then
            # unescape each field.
            f = [re.sub(r"\\(.)", r"\1", p) for p in re.split(r"(?<!\\):", line)]
            if len(f) < 6:
                continue
            ssid = f[0] or "(hidden)"
            bssid = (f[1] or "").upper() or None
            key = bssid or (ssid, f[2])  # one row per AP (BSSID), not per SSID
            if key in seen:
                continue
            seen.add(key)
            try:
                freq = int(re.sub(r"\D", "", f[5]) or 0)
            except ValueError:
                freq = 0
            band = "6GHz" if freq >= 5925 else "5GHz" if freq >= 5000 else "2.4GHz" if freq else None
            aps.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": int(f[2]) if f[2].isdigit() else None,
                "band": band,
                "security": (f[3] or "OPEN").strip(),
                "signal": int(f[4]) if f[4].isdigit() else None,
            })
    return aps


# ── WiFi monitor-mode survey (optional — needs a monitor-capable adapter) ────
# Managed-mode scan_wifi() sees SSIDs+encryption. A monitor-mode adapter (e.g.
# Alfa AWUS036ACH/ACM) passively captures ALL 802.11 frames, giving per-AP
# client counts, hidden SSIDs (BSSID even when cloaked), and channel use — a
# much richer picture for onboarding scoping. Passive only; we never inject.

def _band_for_channel(ch: int | None) -> str | None:
    if not ch:
        return None
    return "2.4GHz" if ch <= 14 else "6GHz" if ch >= 233 else "5GHz"


def parse_airodump_csv(text: str) -> dict:
    """Parse an airodump-ng CSV dump into {aps, clients}. Pure function so the
    parsing is testable without hardware."""
    lines = text.splitlines()
    # The file has two sections: APs, then a blank line + a 'Station MAC' header.
    split_at = next((i for i, ln in enumerate(lines) if ln.strip().startswith("Station MAC")), len(lines))
    ap_rows, sta_rows = lines[:split_at], lines[split_at:]

    def cells(ln: str) -> list[str]:
        return [c.strip() for c in ln.split(",")]

    # Clients: map station → associated BSSID; count per BSSID.
    clients_by_bssid: dict[str, int] = {}
    clients: list[dict] = []
    for ln in sta_rows[1:]:
        c = cells(ln)
        if len(c) < 6 or not re.match(r"[0-9A-Fa-f:]{17}", c[0]):
            continue
        bssid = c[5].upper()
        clients.append({"mac": c[0].upper(), "bssid": bssid if bssid != "(NOT ASSOCIATED)" else None,
                        "signal": int(c[3]) if c[3].lstrip("-").isdigit() else None})
        if bssid and bssid != "(NOT ASSOCIATED)":
            clients_by_bssid[bssid] = clients_by_bssid.get(bssid, 0) + 1

    aps: list[dict] = []
    for ln in ap_rows[1:]:  # skip header
        c = cells(ln)
        if len(c) < 14 or not re.match(r"[0-9A-Fa-f:]{17}", c[0]):
            continue
        bssid = c[0].upper()
        ch = int(c[3]) if c[3].lstrip("-").isdigit() else None
        essid = c[13]
        sec = " ".join(x for x in (c[5], c[6], c[7]) if x).strip() or "OPEN"
        aps.append({
            "bssid": bssid,
            "ssid": essid or "(hidden)",
            "hidden": not essid,
            "channel": ch,
            "band": _band_for_channel(ch),
            "security": sec,
            "signal": int(c[8]) if c[8].lstrip("-").isdigit() else None,
            "clients": clients_by_bssid.get(bssid, 0),
        })
    return {"aps": aps, "clients": clients}


def monitor_wifi(mon_iface: str, seconds: int) -> list[dict]:
    """Put the adapter in monitor mode, capture with airodump-ng for `seconds`
    (it channel-hops automatically), parse, and restore. UNTESTED against real
    hardware — written for when the Alfa card arrives; degrades if tools/adapter
    absent."""
    if not (have("airodump-ng") and mon_iface):
        return []
    started_managed = False
    dev = mon_iface
    try:
        if have("airmon-ng"):
            run(["airmon-ng", "check", "kill"], 15)
            rc, out, _ = run(["airmon-ng", "start", mon_iface], 20)
            m = re.search(r"(monitor mode.*enabled.*?(\w+mon\w*|\w+))", out)
            dev = (m.group(2) if m else mon_iface + "mon")
            started_managed = True
        else:
            run(["ip", "link", "set", mon_iface, "down"], 10)
            run(["iw", "dev", mon_iface, "set", "type", "monitor"], 10)
            run(["ip", "link", "set", mon_iface, "up"], 10)
        prefix = "/tmp/snapshot-wifi"
        run(["rm", "-f"] + [prefix + s for s in ("-01.csv", "-01.cap")], 5)
        # airodump runs until timeout; `run` kills it at the deadline.
        run(["airodump-ng", "--output-format", "csv", "--write-interval", "1", "-w", prefix, dev],
            seconds + 3)
        try:
            with open(prefix + "-01.csv") as f:
                parsed = parse_airodump_csv(f.read())
            return parsed["aps"]
        except FileNotFoundError:
            return []
    finally:
        # Restore managed mode so the laptop's WiFi works again.
        if have("airmon-ng") and started_managed:
            run(["airmon-ng", "stop", dev], 15)
            if have("nmcli"):
                run(["nmcli", "radio", "wifi", "on"], 10)
        elif have("iw"):
            run(["ip", "link", "set", dev, "down"], 10)
            run(["iw", "dev", dev, "set", "type", "managed"], 10)
            run(["ip", "link", "set", dev, "up"], 10)


# ── Merge + assemble ─────────────────────────────────────────────────────────

def merge_hosts(*sources: dict[str, dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for src in sources:
        for ip, rec in src.items():
            cur = merged.setdefault(ip, {"ipv4": ip})
            for k, v in rec.items():
                if k == "discovered_by":
                    cur.setdefault("discovered_by", [])
                    for m in v:
                        if m not in cur["discovered_by"]:
                            cur["discovered_by"].append(m)
                elif v and not cur.get(k):
                    cur[k] = v
    return sorted(merged.values(), key=lambda h: tuple(int(x) for x in h["ipv4"].split(".")))


def attach_mdns(hosts: list[dict], mdns: dict[str, list[str]]) -> None:
    for h in hosts:
        svcs = mdns.get(h["ipv4"])
        if svcs:
            h["mdns_services"] = svcs
            if "mdns" not in h.get("discovered_by", []):
                h.setdefault("discovered_by", []).append("mdns")


def parse_dhcp_discover(out: str) -> list[dict]:
    """Parse nmap broadcast-dhcp-discover output into one entry per responding
    DHCP server (deduped by server identifier)."""
    servers, cur = [], None
    for line in out.splitlines():
        s = line.strip().lstrip("|_").strip()
        if re.match(r"Response \d+ of \d+", s):
            if cur:
                servers.append(cur)
            cur = {}
            continue
        if cur is None:
            continue
        m = re.match(r"([A-Za-z ]+):\s*(.+)", s)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2).strip()
        if key == "server identifier":
            cur["server"] = val
        elif key == "ip offered":
            cur["offered_ip"] = val
        elif key == "router":
            cur["router"] = val
        elif key.startswith("domain name server"):
            cur["dns"] = val
    if cur:
        servers.append(cur)
    seen, uniq = set(), []
    for sv in servers:
        sid = sv.get("server") or sv.get("router") or sv.get("offered_ip")
        if sid and sid not in seen:
            seen.add(sid)
            uniq.append(sv)
    return uniq


def dhcp_probe(iface: str | None = None) -> dict:
    """Broadcast a single DHCP DISCOVER and record every server that OFFERs.
    More than one distinct server on a segment = a rogue/second DHCP — a
    man-in-the-middle vector (malicious gateway/DNS) or a "someone plugged in a
    second router" misconfig. Uses nmap's broadcast-dhcp-discover NSE."""
    if not have("nmap"):
        return {"servers": [], "count": 0}
    cmd = ["nmap", "--script", "broadcast-dhcp-discover"]
    if iface:
        cmd += ["-e", iface]
    _, out, _ = run(cmd, 45)
    servers = parse_dhcp_discover(out)
    return {"servers": servers, "count": len(servers)}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def circuit_health() -> dict:
    """Internet-circuit quality: packet loss / latency / jitter to a public
    anchor, plus double-NAT detection from the first traceroute hops. Low-
    profile — a short ping + a shallow trace, both outbound (never touches LAN
    hosts)."""
    out: dict = {}
    _, o, _ = run(["ping", "-n", "-c", "20", "-i", "0.2", "-W", "1", "8.8.8.8"], 30)
    if o:
        m = re.search(r"(\d+(?:\.\d+)?)% packet loss", o)
        if m:
            out["loss_pct"] = float(m.group(1))
        r = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/([\d.]+)", o)
        if r:
            out["latency_ms"] = round(float(r.group(1)), 1)
            out["jitter_ms"] = round(float(r.group(2)), 1)
    if have("traceroute"):
        _, t, _ = run(["traceroute", "-n", "-w", "1", "-q", "1", "-m", "6", "8.8.8.8"], 30)
        hops = re.findall(r"^\s*\d+\s+((?:\d{1,3}\.){3}\d{1,3})", t or "", re.M)
        lead = 0
        for hop in hops:
            if _is_private(hop):
                lead += 1
            else:
                break
        out["first_hops"] = hops[:5]
        out["private_lead_hops"] = lead
        out["double_nat"] = lead >= 2
    return out


def ipv6_ra(iface: str, seconds: int, passive: bool) -> dict:
    """Detect IPv6 Router Advertisements. >1 distinct router = rogue RA — an
    IPv6 man-in-the-middle path (the twin of rogue DHCP). rdisc6 solicits
    (active); tcpdump just listens (passive-safe)."""
    routers: set = set()
    if iface and have("rdisc6") and not passive:
        _, o, _ = run(["rdisc6", "-1", "-w", "3000", iface], 12)
        for m in re.finditer(r"from\s+(fe80::[0-9a-f:]+)", o or "", re.I):
            routers.add(m.group(1).lower())
    if iface and not routers and have("tcpdump"):
        _, o, _ = run(["tcpdump", "-i", iface, "-c", "4", "-nn", "-l", "icmp6", "and", "ip6[40]==134"], min(seconds, 12) + 5)
        for m in re.finditer(r"(fe80::[0-9a-f:]+)\s*>\s*\S+:\s*ICMP6, router advertisement", o or "", re.I):
            routers.add(m.group(1).lower())
    return {"present": bool(routers), "routers": sorted(routers), "count": len(routers)}


def collect(args) -> dict:
    started = time.time()
    started_iso = now_iso()
    mode = "passive" if args.passive else "active"

    iface_info = detect_interface(args.iface)
    iface = iface_info.get("name")
    log(f"interface: {iface} {iface_info.get('ipv4')} ({iface_info.get('cidr')}), mode={mode}")

    steps: list[dict] = []

    def step(name: str, fn):
        t0 = time.time()
        try:
            res = fn()
            steps.append({"step": name, "ok": True, "seconds": round(time.time() - t0, 1)})
            return res
        except Exception as e:  # noqa: BLE001
            steps.append({"step": name, "ok": False, "error": str(e)[:200]})
            log(f"  {name} failed: {e}")
            return None

    arp = nmap = {}
    duplicate_ips: list = []
    if not args.passive and iface:
        log("arp-scan…")
        arp, duplicate_ips = step("arp_scan", lambda: run_arp_scan(iface)) or ({}, [])
        target = iface_info.get("cidr") or ""
        if target:
            log(f"nmap {target} (fingerprint ports + NSE)… this is the slow part")
            nmap = step("nmap", lambda: run_nmap(target, args.nmap_timeout)) or {}

    passive_hosts = {}
    if args.passive and iface:
        log(f"passive sniff ({args.listen}s)…")
        passive_hosts = step("passive_sniff", lambda: passive_sniff(iface, args.listen)) or {}

    log("mDNS browse…")
    mdns = step("mdns", lambda: browse_mdns(min(args.listen, 15))) or {}
    log("LLDP/CDP capture…")
    lldp = step("lldp", lambda: capture_lldp(iface, args.listen)) or [] if iface else []
    log("Spanning-tree (BPDU) listen…")
    stp = step("stp", lambda: stp_probe(iface, args.listen)) if iface else {"present": False}
    wifi = []
    if not args.no_wifi:
        if args.wifi_monitor:
            log(f"WiFi monitor-mode survey on {args.wifi_monitor} ({args.wifi_seconds}s)…")
            wifi = step("wifi_monitor", lambda: monitor_wifi(args.wifi_monitor, args.wifi_seconds)) or []
        if not wifi:
            log("WiFi scan (managed)…")
            wifi = step("wifi", scan_wifi) or []

    hosts = merge_hosts(arp, nmap, passive_hosts)
    attach_mdns(hosts, mdns)

    # SNMP topology — target the gateway + anything that looks like network gear
    # or exposed 161. Always runs (all scans are with customer consent).
    gw = iface_info.get("gateway")
    NETGEAR = re.compile(r"ubiquiti|cisco|aruba|netgear|mikrotik|fortinet|meraki|juniper|hpe?\b|hewlett|sonicwall|palo alto|extreme", re.I)
    snmp_targets = []
    if gw:
        snmp_targets.append(gw)
    for h in hosts:
        ip = h["ipv4"]
        if ip in snmp_targets:
            continue
        if any(p.get("port") == 161 for p in h.get("open_ports", [])) or NETGEAR.search(h.get("vendor") or ""):
            snmp_targets.append(ip)
    communities = [c.strip() for c in (args.snmp_community or "public").split(",") if c.strip()]
    cidr = iface_info.get("cidr")
    # onesixtyone: sweep the subnet for every SNMP responder + working community,
    # then feed those into the topology walk (active only).
    if not args.passive and cidr:
        log("SNMP discovery (onesixtyone)…")
        disc = step("snmp_discover", lambda: snmp_discover(cidr, communities)) or {}
        for ip, info in disc.items():
            if ip not in snmp_targets:
                snmp_targets.append(ip)
            if info.get("community") and info["community"] not in communities:
                communities.append(info["community"])
    log(f"SNMP topology ({len(snmp_targets)} target(s), communities {communities})…")
    snmp = step("snmp", lambda: snmp_topology(snmp_targets, communities)) or {"devices": [], "edges": []}

    # DNS (reverse + AXFR), NetBIOS names, WAN speed — active-side enrichment.
    dns = {"servers": [], "domains": [], "reverse": {}, "axfr": {}, "axfr_open": False}
    netbios: dict = {}
    dhcp = {"servers": [], "count": 0}
    wan = None
    if not args.passive:
        log("DNS recon (reverse + AXFR attempt)…")
        dns = step("dns", lambda: dns_recon(hosts, gw, [])) or dns
        if cidr:
            log("NetBIOS sweep…")
            netbios = step("netbios", lambda: netbios_scan(cidr)) or {}
            for h in hosts:
                if h["ipv4"] in netbios:
                    h["netbios_name"] = netbios[h["ipv4"]]
        log("DHCP probe (rogue-server check)…")
        dhcp = step("dhcp", lambda: dhcp_probe(iface)) or dhcp
    # Public/WAN IP is cheap and always worth having (one outbound request);
    # the speed test is opt-in because it saturates the circuit. When both run,
    # the speed test's own ISP/IP readings win (cleaner than the echo service).
    log("Public IP lookup…")
    wan = step("public_ip", public_ip) or {}
    if args.speedtest:
        log("WAN speed test (saturates the circuit ~30s)…")
        st = step("speedtest", speed_test)
        if st:
            wan.update({k: v for k, v in st.items() if v is not None})
    wan = wan or None

    # IPv6 rogue-RA (listen — passive-safe) + circuit health run in both modes.
    ipv6 = (step("ipv6_ra", lambda: ipv6_ra(iface, args.listen, args.passive)) if iface else None) or {"present": False}
    log("Circuit health (loss/latency + double-NAT)…")
    circuit = step("circuit", circuit_health) or {}

    # Gateway / firewall identity — combine host record + any SNMP identity.
    gw_host = next((h for h in hosts if h["ipv4"] == gw), None)
    gw_snmp = next((d for d in snmp["devices"] if d["ip"] == gw), None)
    gateway = None
    if gw:
        titles = [p.get("title") for p in (gw_host or {}).get("open_ports", []) if p.get("title")]
        # nmap reports redirects as "Did not follow redirect to https://opnsense/"
        # — the useful bit is the host in that URL.
        clean_titles = []
        for t in titles:
            m = re.search(r"redirect to https?://([^/\s]+)", t or "")
            clean_titles.append(m.group(1) if m else t)
        identity = ((gw_snmp or {}).get("sysdescr")
                    or (gw_host or {}).get("hostname")
                    or (gw_host or {}).get("dns_name")
                    or (gw_host or {}).get("netbios_name")
                    or (clean_titles[0] if clean_titles else None))
        gateway = {
            "ipv4": gw,
            "vendor": (gw_host or {}).get("vendor"),
            "identity": identity,
            "role_guess": (gw_snmp or {}).get("role_guess") or "router/firewall",
        }

    subnets = sorted({str(ipaddress.ip_network(f"{h['ipv4']}/24", strict=False)) for h in hosts})
    vlans = sorted({n["vlan"] for n in lldp if n.get("vlan")})

    coverage = "no hosts found"
    if hosts:
        coverage = (
            f"single broadcast domain ({iface_info.get('cidr')}) from this port; "
            + (f"LLDP indicates VLAN(s) {vlans} — other segments not reachable from here"
               if vlans else "no VLAN tags seen (looks flat / unmanaged switch)")
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "started_at": started_iso,
            "finished_at": now_iso(),
            "duration_seconds": round(time.time() - started),
            "mode": mode,
            "collector_version": COLLECTOR_VERSION,
            "site_label": args.site,
            "location": args.location,
            "operator": args.operator,
            "interface": iface_info,
            "coverage_note": coverage,
            "steps": steps,
            "tools_present": {t: have(t) for t in ("nmap", "arp-scan", "tcpdump", "avahi-browse", "lldpctl", "nmcli", "snmpwalk")},
        },
        "hosts": hosts,
        "network": {
            "subnets_seen": subnets,
            "vlans_seen": [{"id": v, "source": "lldp"} for v in vlans],
            "lldp_neighbors": lldp,
            "gateway": gateway,
            "stp": stp,
            "snmp_devices": snmp["devices"],
            "topology_edges": snmp["edges"],
            "dns": dns,
            "netbios": netbios,
            "dhcp": dhcp,
            "duplicate_ips": duplicate_ips,
            "ipv6_ra": ipv6,
            "circuit": circuit,
            "wan": wan,
        },
        "wifi": wifi,
    }


# ── Demo snapshot (no network needed — for building the report side) ─────────

def demo_snapshot() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "started_at": "2026-07-18T14:02:00+00:00",
            "finished_at": "2026-07-18T14:11:20+00:00",
            "duration_seconds": 560,
            "mode": "active",
            "collector_version": COLLECTOR_VERSION,
            "site_label": "Acme Dental (DEMO)",
            "location": "reception jack",
            "operator": "tzvi",
            "interface": {"name": "eth0", "mac": "dc:a6:32:aa:bb:cc", "ipv4": "10.0.0.50", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1"},
            "coverage_note": "single broadcast domain (10.0.0.0/24) from this port; no VLAN tags seen (looks flat / unmanaged switch)",
            "steps": [{"step": "arp_scan", "ok": True, "seconds": 6.2}, {"step": "nmap", "ok": True, "seconds": 512.0}],
            "tools_present": {"nmap": True, "arp-scan": True, "tcpdump": True, "avahi-browse": True, "lldpctl": False, "nmcli": True},
        },
        "hosts": [
            {"ipv4": "10.0.0.1", "mac": "18:e8:29:11:22:33", "vendor": "Ubiquiti Inc", "hostname": "UDM-Pro", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "Linux 4.x", "accuracy": 95}, "open_ports": [{"port": 443, "proto": "tcp", "service": "https", "title": "UniFi OS"}, {"port": 22, "proto": "tcp", "service": "ssh"}]},
            {"ipv4": "10.0.0.10", "mac": "00:50:56:9a:00:01", "vendor": "VMware", "hostname": "esxi-01", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "VMware ESXi 7.0", "accuracy": 92}, "open_ports": [{"port": 443, "proto": "tcp", "service": "https", "title": "VMware ESXi"}, {"port": 902, "proto": "tcp", "service": "vmware-auth"}]},
            {"ipv4": "10.0.0.20", "mac": "00:11:32:aa:bb:01", "vendor": "Synology", "hostname": "NAS01", "discovered_by": ["arp", "nmap"],
             "open_ports": [{"port": 445, "proto": "tcp", "service": "microsoft-ds"}, {"port": 5001, "proto": "tcp", "service": "https", "title": "Synology DSM"}],
             "smb": {"os": "Windows 6.1", "smbv1": True, "signing": "not_required", "shares": [{"name": "public", "anonymous": True, "access": "READ"}, {"name": "backups", "anonymous": True, "access": "WRITE"}]}},
            {"ipv4": "10.0.0.31", "mac": "ac:cc:8e:11:00:01", "vendor": "Axis Communications", "hostname": "AXIS-lobby", "discovered_by": ["arp", "nmap", "mdns"],
             "open_ports": [{"port": 554, "proto": "tcp", "service": "rtsp"}, {"port": 80, "proto": "tcp", "service": "http", "title": "AXIS Login"}], "mdns_services": ["_rtsp._tcp"]},
            {"ipv4": "10.0.0.32", "mac": "ac:cc:8e:11:00:02", "vendor": "Axis Communications", "hostname": "AXIS-hall", "discovered_by": ["arp", "nmap"],
             "open_ports": [{"port": 554, "proto": "tcp", "service": "rtsp"}, {"port": 80, "proto": "tcp", "service": "http"}]},
            {"ipv4": "10.0.0.40", "mac": "3c:2a:f4:00:aa:01", "vendor": "Brother", "hostname": "BRN3C2AF4", "discovered_by": ["arp", "mdns"],
             "open_ports": [{"port": 9100, "proto": "tcp", "service": "jetdirect"}, {"port": 631, "proto": "tcp", "service": "ipp"}], "mdns_services": ["_ipp._tcp", "_pdl-datastream._tcp"]},
            {"ipv4": "10.0.0.55", "mac": "b8:27:eb:00:00:aa", "vendor": "Raspberry Pi Foundation", "hostname": "unknown-pi", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "Linux", "accuracy": 88}, "open_ports": [{"port": 80, "proto": "tcp", "service": "http", "title": "DVR WebViewer"}, {"port": 6379, "proto": "tcp", "service": "redis", "unauth": True}]},
            {"ipv4": "10.0.0.101", "mac": "f0:9f:c2:00:00:01", "vendor": "Dell", "hostname": "DESKTOP-A1B2C3", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "Microsoft Windows 10", "accuracy": 96}, "open_ports": [{"port": 3389, "proto": "tcp", "service": "ms-wbt-server"}, {"port": 445, "proto": "tcp", "service": "microsoft-ds"}]},
            {"ipv4": "10.0.0.150", "mac": "00:04:f2:00:00:aa", "vendor": "Polycom", "hostname": "phone-reception", "discovered_by": ["arp"],
             "open_ports": [{"port": 5060, "proto": "tcp", "service": "sip"}]},
        ],
        "network": {
            "subnets_seen": ["10.0.0.0/24"],
            "vlans_seen": [],
            "lldp_neighbors": [{"local_port": "eth0", "switch_name": "SW-CORE", "switch_port": "Gi1/0/1", "port_descr": "Uplink", "vlan": 1, "mgmt_ip": "10.0.0.2", "poe": True, "source": "lldpd"}],
            "gateway": {"ipv4": "10.0.0.1", "vendor": "Ubiquiti Inc", "identity": "UniFi Dream Machine Pro", "role_guess": "router/firewall"},
            "stp": {"present": True, "version": "stp", "root": {"priority": 32768, "mac": "00:11:32:aa:bb:01"}, "designated_bridge": {"priority": 32768, "mac": "18:e8:29:11:22:33"}, "root_pathcost": 4, "is_root_here": False},
            "snmp_devices": [
                {"ip": "10.0.0.2", "sysname": "SW-CORE", "sysdescr": "UniFi Switch 48 PoE", "role_guess": "switch",
                 "neighbor_count": 2, "neighbors": [
                     {"local_port": "1", "neighbor_name": "UDM-Pro", "neighbor_port": "Port 9"},
                     {"local_port": "24", "neighbor_name": "SW-FLOOR2", "neighbor_port": "Gi1/0/48"}],
                 "interfaces": 52, "interfaces_up": 19, "community_used": "public"},
                {"ip": "10.0.0.3", "sysname": "SW-FLOOR2", "sysdescr": "UniFi Switch 24", "role_guess": "switch",
                 "neighbor_count": 1, "neighbors": [
                     {"local_port": "48", "neighbor_name": "SW-CORE", "neighbor_port": "Port 24"}],
                 "interfaces": 26, "interfaces_up": 11, "community_used": "public"},
            ],
            "topology_edges": [
                {"from": "SW-CORE", "from_port": "1", "to": "UDM-Pro", "to_port": "Port 9"},
                {"from": "SW-CORE", "from_port": "24", "to": "SW-FLOOR2", "to_port": "Gi1/0/48"},
                {"from": "SW-FLOOR2", "from_port": "48", "to": "SW-CORE", "to_port": "Port 24"},
            ],
            "dns": {
                "servers": ["10.0.0.1"], "domains": ["acme.local"], "axfr_open": True,
                "reverse": {"10.0.0.20": "nas01.acme.local", "10.0.0.101": "reception-pc.acme.local"},
                "axfr": {"acme.local@10.0.0.1": [
                    {"name": "dc1.acme.local", "type": "A", "value": "10.0.0.6"},
                    {"name": "nas01.acme.local", "type": "A", "value": "10.0.0.20"},
                    {"name": "timeclock.acme.local", "type": "A", "value": "10.0.0.77"}]},
            },
            "netbios": {"10.0.0.101": "RECEPTION-PC", "10.0.0.6": "DC1"},
            "dhcp": {"count": 2, "servers": [
                {"server": "10.0.0.1", "offered_ip": "10.0.0.55", "router": "10.0.0.1", "dns": "10.0.0.1"},
                {"server": "10.0.0.240", "offered_ip": "10.0.0.88", "router": "10.0.0.240", "dns": "8.8.8.8"},
            ]},
            "duplicate_ips": [{"ip": "10.0.0.44", "macs": ["00:1a:2b:3c:4d:5e", "aa:bb:cc:dd:ee:ff"]}],
            "ipv6_ra": {"present": True, "count": 2, "routers": ["fe80::1", "fe80::dead:beef"]},
            "circuit": {"loss_pct": 0.0, "latency_ms": 14.0, "jitter_ms": 3.0, "double_nat": True, "private_lead_hops": 2, "first_hops": ["10.0.0.1", "192.168.100.1", "203.0.113.1"]},
            "wan": {"public_ip": "203.0.113.47", "download_mbps": 187.4, "upload_mbps": 21.6, "ping_ms": 12.3, "isp": "Optimum", "geo": "New York, NY", "server": "New York, NY"},
        },
        "wifi": [
            {"ssid": "Acme-Corp", "bssid": "B8:27:EB:1A:2B:01", "channel": 36, "band": "5GHz", "security": "WPA2", "signal": 82},
            {"ssid": "Acme-Corp", "bssid": "B8:27:EB:1A:2B:02", "channel": 149, "band": "5GHz", "security": "WPA2", "signal": 66},
            {"ssid": "Acme-Guest", "bssid": "B8:27:EB:1A:2B:03", "channel": 6, "band": "2.4GHz", "security": "OPEN", "signal": 74},
            {"ssid": "linksys", "bssid": "00:14:BF:9C:5D:1E", "channel": 11, "band": "2.4GHz", "security": "WPA2", "signal": 40},
        ],
    }


def _parse_version(text: str) -> str | None:
    m = re.search(r"""COLLECTOR_VERSION\s*=\s*["']([0-9]+(?:\.[0-9]+)*)["']""", text)
    return m.group(1) if m else None


def check_for_update(assume_yes: bool = False) -> None:
    """GitHub is the source of truth. Before scanning, see whether this copy is
    behind and offer to update. Never blocks: any failure (offline, not a git
    checkout) prints a soft note and the scan proceeds — field work must never
    be stopped by an update check.

    A git checkout is checked with `git fetch` (immediate, not CDN-cached); a
    loose copy falls back to the raw file over HTTP (best-effort, and raw is
    cached ~5 min so it can lag a fresh push)."""
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.isdir(os.path.join(here, ".git")) and have("git"):
        _update_via_git(here, assume_yes)
    else:
        _update_via_http()


def _update_via_git(here: str, assume_yes: bool) -> None:
    # sudo runs git as root in a user-owned tree → mark it safe to avoid the
    # "dubious ownership" refusal.
    gh = ["git", "-c", f"safe.directory={here}", "-C", here]
    rc, _, err = run(gh + ["fetch", "--quiet", "origin", "main"], 30)
    if rc != 0:
        log(f"update check skipped (git fetch: {err.strip()[:60]})")
        return
    _, local, _ = run(gh + ["rev-parse", "HEAD"], 10)
    _, remote, _ = run(gh + ["rev-parse", "origin/main"], 10)
    if not remote.strip() or local.strip() == remote.strip():
        log(f"collector up to date (v{COLLECTOR_VERSION})")
        return
    _, cnt, _ = run(gh + ["rev-list", "--count", "HEAD..origin/main"], 10)
    _, remote_src, _ = run(gh + ["show", "origin/main:collect.py"], 15)
    newv = _parse_version(remote_src) or "newer"
    print(f"\n\033[33m▲ Update available: v{newv} — you have v{COLLECTOR_VERSION} "
          f"({cnt.strip() or '?'} commit(s) behind).\033[0m")
    if not (assume_yes or input("  Pull the update now? [Y/n]: ").strip().lower() in ("", "y", "yes")):
        return
    rc, out, err = run(gh + ["pull", "--ff-only", "origin", "main"], 60)
    if rc != 0:
        print(f"  git pull failed: {(err or out).strip()}\n  Update manually: git -C {here} pull\n")
        return
    print("  Updated. Restarting with the new version…\n")
    os.execv(sys.executable, [sys.executable, *sys.argv])


def _update_via_http() -> None:
    try:
        req = urllib.request.Request(REPO_RAW_URL, headers={"User-Agent": "network-snapshot"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            remote = _parse_version(resp.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001 — offline / blocked / rate-limited
        log(f"update check skipped ({e})")
        return
    if not remote:
        return
    try:
        if tuple(int(x) for x in remote.split(".")) <= tuple(int(x) for x in COLLECTOR_VERSION.split(".")):
            log(f"collector up to date (v{COLLECTOR_VERSION})")
            return
    except ValueError:
        return
    print(f"\n\033[33m▲ Update available: v{remote} (you have v{COLLECTOR_VERSION}).\033[0m")
    print(f"  This copy is not a git checkout. Clone the source of truth:\n"
          f"    git clone {REPO_WEB_URL}\n")


def submit(url: str, secret: str | None, snapshot: dict, timeout: int = 60) -> None:
    """POST the snapshot to a collection webhook (n8n). Best-effort: the local
    file is always written first, so a failed upload never loses a scan."""
    body = json.dumps(snapshot).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if secret:
        req.add_header("x-snapshot-secret", secret)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            log(f"submitted → {url}  (HTTP {resp.status})")
    except Exception as e:  # noqa: BLE001
        log(f"submit FAILED ({e}) — local file is still saved, upload later")


def main() -> int:
    ap = argparse.ArgumentParser(description="Network Snapshot collector")
    ap.add_argument("-o", "--output", help="write snapshot JSON here (default: stdout)")
    ap.add_argument("--site", default=None, help="prospect / site label (the merge key)")
    ap.add_argument("--location", default=None, help="where this drop is (e.g. 'server room / camera VLAN') — context for a multi-drop report, not a merge directive")
    ap.add_argument("--operator", default=None, help="who ran the scan")
    ap.add_argument("--passive", action="store_true", help="listen only — no arp-scan/nmap probing")
    ap.add_argument("--iface", default=None, help="force interface (else auto-detect)")
    ap.add_argument("--no-wifi", action="store_true", help="skip the WiFi scan")
    ap.add_argument("--wifi-monitor", default=None, metavar="IFACE",
                    help="monitor-capable adapter (e.g. wlan1) for a richer passive survey — client counts, hidden SSIDs, channel use (needs airodump-ng)")
    ap.add_argument("--wifi-seconds", type=int, default=45, help="monitor-mode capture duration")
    ap.add_argument("--snmp-community", default="public",
                    help="comma-separated SNMP read communities to try for topology (default: public)")
    ap.add_argument("--speedtest", action="store_true",
                    help="run a WAN speed test (saturates the internet circuit for ~30s)")
    ap.add_argument("--listen", type=int, default=20, help="seconds for passive listeners")
    ap.add_argument("--nmap-timeout", type=int, default=1800, help="hard cap on nmap (s)")
    ap.add_argument("--demo", action="store_true", help="emit a sample snapshot, no network")
    ap.add_argument("--check", action="store_true", help="check for required tools (offer to install) and exit")
    ap.add_argument("--yes", action="store_true", help="auto-install missing tools without prompting")
    ap.add_argument("--skip-check", action="store_true", help="skip the tool preflight before scanning")
    ap.add_argument("--submit", default=os.environ.get("SNAPSHOT_SUBMIT_URL"),
                    help="POST the snapshot to this webhook after scanning (or set SNAPSHOT_SUBMIT_URL)")
    ap.add_argument("--submit-secret", default=os.environ.get("SNAPSHOT_SUBMIT_SECRET"),
                    help="shared secret sent as x-snapshot-secret (or set SNAPSHOT_SUBMIT_SECRET)")
    ap.add_argument("--no-submit", action="store_true",
                    help="skip auto-submit even if submit.conf / env is configured")
    ap.add_argument("--no-update", action="store_true",
                    help="skip the GitHub version check before scanning")
    args = ap.parse_args()

    log(f"network-snapshot collector v{COLLECTOR_VERSION}  ({REPO_WEB_URL})")

    # GitHub is the source of truth — check for a newer version first (skip for
    # offline demo runs). Degrades gracefully if offline.
    if not args.demo and not args.no_update:
        check_for_update(assume_yes=args.yes)

    # Auto-submit config: a `submit.conf` next to this script ({"url","secret"})
    # makes every scan upload with no flag. A file survives sudo (which strips
    # env vars); env/flags still override it. This is what "always auto-upload"
    # relies on in the field.
    if not args.no_submit and not args.submit:
        conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "submit.conf")
        if os.path.exists(conf_path):
            try:
                with open(conf_path) as cf:
                    conf = json.load(cf)
                args.submit = conf.get("url")
                args.submit_secret = args.submit_secret or conf.get("secret")
            except (ValueError, OSError) as e:
                log(f"submit.conf unreadable ({e}) — skipping auto-submit")
    if args.no_submit:
        args.submit = None

    if args.check:
        doctor(assume_yes=args.yes)
        return 0
    if not args.demo and not args.skip_check:
        doctor(assume_yes=args.yes)

    snapshot = demo_snapshot() if args.demo else collect(args)
    text = json.dumps(snapshot, indent=2)
    # Always write the local file first — it's the safety net.
    out = args.output or (f"snapshot-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json" if args.submit else None)
    if out:
        with open(out, "w") as f:
            f.write(text)
        log(f"wrote {out}  ({len(snapshot['hosts'])} hosts)")
    elif not args.submit:
        print(text)
    if args.submit:
        submit(args.submit, args.submit_secret, snapshot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
