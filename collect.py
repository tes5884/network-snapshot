#!/usr/bin/env python3
"""
Network Snapshot — collector
============================

Runs on a laptop plugged into a prospect's network. Orchestrates a handful of
standard tools, then emits ONE structured JSON file (the "snapshot") describing
what it found — hosts, open ports/services, LLDP/VLAN topology, and nearby WiFi.

The snapshot JSON is the whole contract. Everything downstream (categorization,
the AI narrative, the report) consumes this file and nothing else, so the report
side can live in TEQhub today and move elsewhere later without touching this.

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
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

COLLECTOR_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"

# Curated "fingerprint" ports — enough to identify device roles without the
# noise/time of a full 65k sweep. RTSP=camera, 9100=printer, 3389=RDP, etc.
FINGERPRINT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,161,443,445,515,554,587,631,"
    "993,995,1433,1521,1723,1883,2049,3128,3306,3389,5000,5060,5432,5900,"
    "8000,8080,8443,8888,9100,32400,49152"
)
# NSE scripts that reveal roles/risks without being aggressive.
NSE_SCRIPTS = "smb-os-discovery,smb-enum-shares,snmp-info,http-title,ssl-cert"


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

def run_arp_scan(iface: str) -> dict[str, dict]:
    hosts: dict[str, dict] = {}
    if not have("arp-scan"):
        return hosts
    rc, out, _ = run(["arp-scan", "--interface", iface, "--localnet", "--retry=2"], 120)
    for line in out.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$", line)
        if m:
            ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
            hosts[ip] = {"mac": mac, "vendor": vendor or None, "discovered_by": ["arp"]}
    return hosts


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
            # http title / ssl cert from NSE
            for scr in p.findall("script"):
                if scr.get("id") == "http-title" and scr.get("output"):
                    entry["title"] = scr.get("output").strip()
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
                    vlan = det.get("vlan", {})
                    neighbors.append({
                        "local_port": name,
                        "switch_name": sw_name,
                        "switch_port": (port.get("id", {}) or {}).get("value") if isinstance(port.get("id"), dict) else port.get("descr"),
                        "vlan": (vlan.get("vlan-id") if isinstance(vlan, dict) else None),
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


# ── WiFi scan ────────────────────────────────────────────────────────────────

def scan_wifi() -> list[dict]:
    aps: list[dict] = []
    if have("nmcli"):
        rc, out, _ = run(
            ["nmcli", "-t", "-f", "SSID,CHAN,SECURITY,SIGNAL,FREQ", "dev", "wifi", "list", "--rescan", "yes"],
            30,
        )
        seen = set()
        for line in out.splitlines():
            f = line.split(":")
            if len(f) < 5:
                continue
            ssid = f[0] or "(hidden)"
            key = (ssid, f[1])
            if key in seen:
                continue
            seen.add(key)
            try:
                freq = int(re.sub(r"\D", "", f[4]) or 0)
            except ValueError:
                freq = 0
            band = "6GHz" if freq >= 5925 else "5GHz" if freq >= 5000 else "2.4GHz" if freq else None
            aps.append({
                "ssid": ssid,
                "channel": int(f[1]) if f[1].isdigit() else None,
                "band": band,
                "security": (f[2] or "OPEN").strip(),
                "signal": int(f[3]) if f[3].isdigit() else None,
            })
    return aps


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
    if not args.passive and iface:
        log("arp-scan…")
        arp = step("arp_scan", lambda: run_arp_scan(iface)) or {}
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
    wifi = []
    if not args.no_wifi:
        log("WiFi scan…")
        wifi = step("wifi", scan_wifi) or []

    hosts = merge_hosts(arp, nmap, passive_hosts)
    attach_mdns(hosts, mdns)

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
            "tools_present": {t: have(t) for t in ("nmap", "arp-scan", "tcpdump", "avahi-browse", "lldpctl", "nmcli")},
        },
        "hosts": hosts,
        "network": {
            "subnets_seen": subnets,
            "vlans_seen": [{"id": v, "source": "lldp"} for v in vlans],
            "lldp_neighbors": lldp,
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
             "smb": {"os": "Windows 6.1", "shares": [{"name": "public", "anonymous": True, "access": "READ"}, {"name": "backups", "anonymous": True, "access": "WRITE"}]}},
            {"ipv4": "10.0.0.31", "mac": "ac:cc:8e:11:00:01", "vendor": "Axis Communications", "hostname": "AXIS-lobby", "discovered_by": ["arp", "nmap", "mdns"],
             "open_ports": [{"port": 554, "proto": "tcp", "service": "rtsp"}, {"port": 80, "proto": "tcp", "service": "http", "title": "AXIS Login"}], "mdns_services": ["_rtsp._tcp"]},
            {"ipv4": "10.0.0.32", "mac": "ac:cc:8e:11:00:02", "vendor": "Axis Communications", "hostname": "AXIS-hall", "discovered_by": ["arp", "nmap"],
             "open_ports": [{"port": 554, "proto": "tcp", "service": "rtsp"}, {"port": 80, "proto": "tcp", "service": "http"}]},
            {"ipv4": "10.0.0.40", "mac": "3c:2a:f4:00:aa:01", "vendor": "Brother", "hostname": "BRN3C2AF4", "discovered_by": ["arp", "mdns"],
             "open_ports": [{"port": 9100, "proto": "tcp", "service": "jetdirect"}, {"port": 631, "proto": "tcp", "service": "ipp"}], "mdns_services": ["_ipp._tcp", "_pdl-datastream._tcp"]},
            {"ipv4": "10.0.0.55", "mac": "b8:27:eb:00:00:aa", "vendor": "Raspberry Pi Foundation", "hostname": "unknown-pi", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "Linux", "accuracy": 88}, "open_ports": [{"port": 80, "proto": "tcp", "service": "http", "title": "DVR WebViewer"}]},
            {"ipv4": "10.0.0.101", "mac": "f0:9f:c2:00:00:01", "vendor": "Dell", "hostname": "DESKTOP-A1B2C3", "discovered_by": ["arp", "nmap"],
             "os_guess": {"name": "Microsoft Windows 10", "accuracy": 96}, "open_ports": [{"port": 3389, "proto": "tcp", "service": "ms-wbt-server"}, {"port": 445, "proto": "tcp", "service": "microsoft-ds"}]},
            {"ipv4": "10.0.0.150", "mac": "00:04:f2:00:00:aa", "vendor": "Polycom", "hostname": "phone-reception", "discovered_by": ["arp"],
             "open_ports": [{"port": 5060, "proto": "tcp", "service": "sip"}]},
        ],
        "network": {
            "subnets_seen": ["10.0.0.0/24"],
            "vlans_seen": [],
            "lldp_neighbors": [{"local_port": "eth0", "switch_name": None, "switch_port": None, "vlan": None, "source": "tcpdump"}],
        },
        "wifi": [
            {"ssid": "Acme-Corp", "channel": 36, "band": "5GHz", "security": "WPA2", "signal": 82},
            {"ssid": "Acme-Guest", "channel": 6, "band": "2.4GHz", "security": "OPEN", "signal": 74},
            {"ssid": "linksys", "channel": 11, "band": "2.4GHz", "security": "WPA2", "signal": 40},
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Network Snapshot collector")
    ap.add_argument("-o", "--output", help="write snapshot JSON here (default: stdout)")
    ap.add_argument("--site", default=None, help="prospect / site label (the merge key)")
    ap.add_argument("--location", default=None, help="where this drop is (e.g. 'server room / camera VLAN') — context for a multi-drop report, not a merge directive")
    ap.add_argument("--operator", default=None, help="who ran the scan")
    ap.add_argument("--passive", action="store_true", help="listen only — no arp-scan/nmap probing")
    ap.add_argument("--iface", default=None, help="force interface (else auto-detect)")
    ap.add_argument("--no-wifi", action="store_true", help="skip the WiFi scan")
    ap.add_argument("--listen", type=int, default=20, help="seconds for passive listeners")
    ap.add_argument("--nmap-timeout", type=int, default=1800, help="hard cap on nmap (s)")
    ap.add_argument("--demo", action="store_true", help="emit a sample snapshot, no network")
    args = ap.parse_args()

    snapshot = demo_snapshot() if args.demo else collect(args)
    text = json.dumps(snapshot, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        log(f"wrote {args.output}  ({len(snapshot['hosts'])} hosts)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
