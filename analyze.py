#!/usr/bin/env python3
"""
Network Snapshot — analyzer (deterministic engine)
==================================================

Turns a collector snapshot (schema 1.0) into a structured *findings model*:
device categories, ranked risk/opportunity flags, and an onboarding-scope
worksheet. Pure stdlib, no rendering, no network — snapshot JSON in, model
dict out.

This model is the seam. The report renderer consumes it to draw HTML, and the
AI narrative layer consumes the same model (via `build_brief`) to write the
executive summary and refine the ambiguous ~20%. Keeping the deterministic
picture separate from both is what lets the report engine move off TEQhub
later without dragging anything with it.

    from analyze import analyze
    model = analyze(json.load(open("snapshot.json")))

Design split (see project notes): ~80% of the categorization is deterministic
here — MAC OUI vendor + open ports + mDNS service types + SNMP role. The AI
only handles narrative, ranking importance, the genuinely ambiguous devices
(flagged `low_confidence` here), and scoping judgement.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict

ANALYZER_VERSION = "0.1.0"

# ── Device categories ────────────────────────────────────────────────────────
# Order = display order = rough "importance to a network picture" order.
CATEGORIES = [
    ("firewall",    "Firewall / Router",   "the edge — what stands between the LAN and the internet"),
    ("switch",      "Switches",            "managed switching fabric"),
    ("ap",          "Access Points",       "wireless infrastructure"),
    ("server",      "Servers",             "always-on hosts serving the business"),
    ("nas",         "Storage / NAS",       "network file storage"),
    ("hypervisor",  "Virtualization",      "hypervisors running virtual machines"),
    ("workstation", "Workstations",        "staff PCs and laptops"),
    ("camera",      "Cameras / NVR",       "video surveillance"),
    ("printer",     "Printers / MFP",      "printers and multifunction devices"),
    ("voip",        "VoIP / Phones",       "IP telephony"),
    ("mobile",      "Mobile / Tablets",    "phones and tablets"),
    ("iot",         "IoT / Smart",         "smart-home and embedded gadgets"),
    ("unknown",     "Unclassified",        "seen on the wire, not confidently identified"),
]
CAT_LABEL = {k: v for k, v, _ in CATEGORIES}
CAT_BLURB = {k: b for k, _, b in CATEGORIES}
CAT_ORDER = {k: i for i, (k, _, _) in enumerate(CATEGORIES)}

# Vendor keyword → category. Matched case-insensitively as substrings against
# the OUI vendor string. First hit wins in the order listed.
VENDOR_HINTS = [
    ("camera",     ["hikvision", "uniview", "reolink", "dahua", "hanwha", "axis communications", "amcrest", "vivotek", "lorex", "geovision", "ubiquiti.*camera"]),
    ("printer",    ["brother", "hewlett", "hp inc", "canon", "epson", "xerox", "lexmark", "ricoh", "kyocera", "zebra", "konica"]),
    ("nas",        ["synology", "qnap", "drobo", "western digital", "netgear.*readynas"]),
    ("voip",       ["polycom", "yealink", "grandstream", "sangoma", "snom", "mitel", "avaya", "cisco.*phone", "ooma"]),
    ("ap",         ["aruba", "ruckus", "meraki", "engenius", "tp-link.*eap"]),
    ("iot",        ["espressif", "sonoff", "itead", "tuya", "ecobee", "nest", "shelly", "lifx", "philips.*hue", "wiz ", "govee", "roku", "amazon technologies", "google.*nest", "lg electronics", "lg innotek", "samsung.*tv", "tesla", "whisker labs", "inventek", "gainspan", "murata", "particle"]),
    ("mobile",     ["apple.*iphone", "apple.*ipad"]),
]

# Printer brands — used to gate the 9100/631 port signal so a Linux box that
# happens to expose a raw-print port isn't mistaken for a printer.
PRINTER_VENDORS = ["brother", "hewlett", "hp inc", "canon", "epson", "xerox", "lexmark", "ricoh", "kyocera", "konica"]
# Vendors that make general-purpose computers (a 9100 here is NOT a printer).
COMPUTER_VENDORS = ["dell", "lenovo", "g-pro", "gigabyte", "asus", "intel", "micro-star", "msi", "apple", "raspberry", "supermicro", "vmware", "pc partner"]

# mDNS service type → category signal.
MDNS_HINTS = [
    ("printer", ["_ipp", "_printer", "_pdl-datastream", "_scanner"]),
    ("camera",  ["_psia", "_cgi", "_rtsp", "_axis-video", "_dahua"]),
    ("iot",     ["_hap", "_esphomelib", "_homekit", "_miio", "_googlecast", "_spotify-connect", "_airplay", "_sonos"]),
    ("voip",    ["_sip"]),
]

# Port → (category, weight). Weight is a nudge, not a verdict.
PORT_HINTS = {
    554:  ("camera", 3),      # rtsp
    9100: ("printer", 2),     # jetdirect (gated by vendor below)
    631:  ("printer", 1),     # ipp
    515:  ("printer", 2),     # lpd
    5060: ("voip", 3),        # sip
    5061: ("voip", 2),
    3389: ("workstation", 1), # rdp
    902:  ("hypervisor", 3),  # vmware auth
}

# Server-ish service ports — presence pushes an otherwise-generic Linux/Windows
# host toward "server".
SERVER_PORTS = {88, 389, 636, 3268, 1433, 3306, 5432, 1883, 8006, 25, 143, 993, 587, 2049, 111, 5985}
DC_PORTS = {88, 389, 636, 3268}  # domain controller tell

WIFI_OPEN = {"OPEN", "", "OPN", "NONE"}
WIFI_WEAK = {"WEP", "WPA"}  # not WPA2/WPA3


def _norm(s):
    return (s or "").lower()


def _vendor_match(vendor, needles):
    v = _norm(vendor)
    return any(re.search(n, v) for n in needles)


def _ports(host):
    return {p.get("port") for p in host.get("open_ports", []) if p.get("port")}


def _services(host):
    return " ".join(_norm(p.get("service")) + " " + _norm(p.get("product"))
                     for p in host.get("open_ports", []))


def _os(host):
    return _norm((host.get("os_guess") or {}).get("name"))


def _name(host):
    return host.get("hostname") or host.get("dns_name") or host.get("netbios_name") or ""


def classify(host, ctx):
    """Return (category, confidence, reasons[]). confidence: 'high'|'med'|'low'."""
    reasons = []
    vendor = host.get("vendor") or ""
    ports = _ports(host)
    os_name = _os(host)
    name = _norm(_name(host))
    mdns = " ".join(_norm(s) for s in host.get("mdns_services", []))
    ip = host.get("ipv4")

    # 1. Gateway is the firewall/router — strongest possible signal.
    if ip and ip == ctx.get("gateway_ip"):
        reasons.append("default gateway for this subnet")
        return "firewall", "high", reasons

    # 2. Known switch/AP from SNMP topology.
    role = ctx.get("snmp_roles", {}).get(ip)
    if role in ("switch", "router", "ap"):
        reasons.append(f"SNMP identified it as a {role}")
        return ("switch" if role != "ap" else "ap"), "high", reasons

    # 3. Camera — vendor, mDNS, model name, or rtsp.
    if _vendor_match(vendor, dict(VENDOR_HINTS)["camera"]):
        reasons.append(f"camera-brand OUI ({vendor})")
        return "camera", "high", reasons
    if any(s in mdns for s in dict(MDNS_HINTS)["camera"]):
        reasons.append("advertises a camera mDNS service")
        return "camera", "high", reasons
    if 554 in ports:
        reasons.append("RTSP (554) open")
        return "camera", "med", reasons
    if re.match(r"(ds-2cd|ipc-|dahua|nvr|cam[-0-9])", name):
        reasons.append(f"camera-style hostname ({name})")
        return "camera", "med", reasons

    # 4. Printer — brand OUI, printer mDNS, printer OS, or raw-print port on a
    #    non-computer host.
    if _vendor_match(vendor, PRINTER_VENDORS):
        reasons.append(f"printer-brand OUI ({vendor})")
        return "printer", "high", reasons
    if "printer" in os_name:
        reasons.append("OS fingerprint says printer")
        return "printer", "high", reasons
    if any(s in mdns for s in dict(MDNS_HINTS)["printer"]):
        reasons.append("advertises a printer mDNS service")
        return "printer", "high", reasons
    if (9100 in ports or 515 in ports) and not _vendor_match(vendor, COMPUTER_VENDORS) and 22 not in ports:
        reasons.append("raw-print port open on a non-computer host")
        return "printer", "med", reasons

    # 5. VoIP.
    if _vendor_match(vendor, dict(VENDOR_HINTS)["voip"]) or 5060 in ports or "_sip" in mdns:
        reasons.append("SIP signalling / phone-brand OUI")
        return "voip", "med", reasons

    # 6. Hypervisor.
    if "esxi" in os_name or "vmware" in _norm(vendor) or 902 in ports or "proxmox" in _services(host) or 8006 in ports:
        reasons.append("hypervisor fingerprint (ESXi/Proxmox/VMware)")
        return "hypervisor", "high", reasons

    # 7. NAS.
    if _vendor_match(vendor, dict(VENDOR_HINTS)["nas"]) or re.search(r"(nas|synology|qnap|diskstation)", name):
        reasons.append("storage-appliance vendor/hostname")
        return "nas", "high", reasons

    # 8. Mobile / tablet.
    if re.search(r"(iphone|ipad|android|pixel|galaxy)", name) or ("ios" in os_name or "android" in os_name):
        reasons.append("mobile OS / hostname")
        return "mobile", "med", reasons

    # 9. IoT — embedded vendor, IoT mDNS, or tiny embedded OS.
    if _vendor_match(vendor, dict(VENDOR_HINTS)["iot"]):
        reasons.append(f"IoT/embedded OUI ({vendor})")
        return "iot", "med", reasons
    if any(s in mdns for s in dict(MDNS_HINTS)["iot"]):
        reasons.append("advertises a smart-home mDNS service")
        return "iot", "med", reasons
    if re.search(r"(lwip|esphome|freertos|contiki)", os_name) or "esphome" in name:
        reasons.append("embedded network stack (ESP/lwIP)")
        return "iot", "med", reasons

    # 10. Switch/AP by fingerprint even without SNMP.
    if _vendor_match(vendor, dict(VENDOR_HINTS)["ap"]):
        reasons.append("access-point vendor OUI")
        return "ap", "med", reasons
    if re.search(r"switch", os_name) or re.search(r"(tl-sg|edgeswitch|gs108|gs110|gs308|catalyst|sg[0-9]{3})", name):
        reasons.append("switch OS fingerprint / model hostname")
        return "switch", "med", reasons
    if 23 in ports and _vendor_match(vendor, ["tp-link", "netgear", "ubiquiti", "cisco", "hewlett", "d-link"]):
        reasons.append("telnet-managed network-gear vendor")
        return "switch", "low", reasons

    # 11. Workstation — desktop OS or RDP.
    if re.search(r"(windows (7|8|10|11|xp|vista))|mac ?os|macos|darwin", os_name) or 3389 in ports:
        reasons.append("desktop OS / RDP present")
        conf = "high" if re.search(r"windows (10|11)|macos", os_name) else "med"
        return "workstation", conf, reasons
    if re.search(r"(desktop-|laptop-|-pc$|-yoga|thinkpad|macbook)", name):
        reasons.append(f"workstation-style hostname ({name})")
        return "workstation", "med", reasons

    # 12. Server — server OS, or a Linux/Windows host exposing server services.
    server_hits = ports & SERVER_PORTS
    if re.search(r"server", os_name) or server_hits or (re.search(r"linux", os_name) and (80 in ports or 443 in ports or 22 in ports)):
        if ports & DC_PORTS:
            reasons.append("domain-controller ports (Kerberos/LDAP)")
        elif server_hits:
            reasons.append("server service ports: " + ", ".join(str(p) for p in sorted(server_hits)))
        else:
            reasons.append("Linux host serving http/ssh")
        conf = "med" if server_hits or "server" in os_name else "low"
        return "server", conf, reasons

    # 13. Give up — record what little we know.
    if vendor and "unknown" not in _norm(vendor):
        reasons.append(f"only the {vendor} OUI is known")
    else:
        reasons.append("no vendor, OS, or service signal")
    return "unknown", "low", reasons


# ── Risk & opportunity assessment ────────────────────────────────────────────

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _finding(sev, kind, title, detail, hosts=None, scope_hint=None):
    return {
        "severity": sev,
        "kind": kind,               # "risk" | "opportunity"
        "title": title,
        "detail": detail,
        "hosts": hosts or [],
        "scope_hint": scope_hint,   # one-line onboarding implication
    }


def assess(snapshot, cats, host_cat):
    net = snapshot.get("network", {})
    hosts = snapshot.get("hosts", [])
    findings = []

    # Flat network / no segmentation.
    vlans = net.get("vlans_seen") or []
    subnets = net.get("subnets_seen") or []
    live = len(hosts)
    mixed = sum(1 for c in ("camera", "iot", "voip") if cats.get(c)) >= 1 and cats.get("workstation")
    if not vlans and live >= 8:
        detail = (f"All {live} discovered devices share one broadcast domain "
                  f"({', '.join(subnets) or 'single subnet'}) with no VLAN tags observed.")
        if mixed:
            detail += " Cameras/IoT/phones sit on the same flat network as staff PCs and servers."
        findings.append(_finding(
            "high" if mixed else "medium", "risk",
            "Flat network — no VLAN segmentation",
            detail,
            scope_hint="Network redesign: VLAN plan separating trust zones (staff / servers / cameras / IoT / guest)."))

    # Anonymous SMB shares.
    read_shares, write_shares = [], []
    for h in hosts:
        for sh in (h.get("smb") or {}).get("shares", []):
            if sh.get("anonymous"):
                entry = f"{h.get('ipv4')} → \\\\{_name(h) or h.get('ipv4')}\\{sh.get('name')} ({sh.get('access','?')})"
                (write_shares if "WRITE" in _norm(sh.get("access")).upper() else read_shares).append(entry)
    if write_shares:
        findings.append(_finding("high", "risk", "Anonymous-writable file shares",
            "SMB shares are writable without authentication — an open door for ransomware and data tampering.",
            hosts=write_shares,
            scope_hint="Lock down share permissions; audit for sensitive data exposure."))
    if read_shares:
        findings.append(_finding("medium", "risk", "Anonymous-readable file shares",
            "SMB shares are readable by anyone on the network with no credentials.",
            hosts=read_shares,
            scope_hint="Review share ACLs during onboarding."))

    # Open / weak WiFi.
    open_ssids, weak_ssids = [], []
    for w in snapshot.get("wifi", []):
        sec = (w.get("security") or "").upper()
        label = f"{w.get('ssid') or '(hidden)'} — ch {w.get('channel')}/{w.get('band')}"
        if sec in WIFI_OPEN:
            open_ssids.append(label)
        elif sec in WIFI_WEAK:
            weak_ssids.append(f"{label} ({sec})")
    if open_ssids:
        guessed_guest = all(re.search(r"guest|public", s, re.I) for s in open_ssids)
        findings.append(_finding(
            "medium" if guessed_guest else "high", "risk",
            "Open (unencrypted) WiFi",
            "Wireless networks with no encryption — traffic is readable and the SSID is joinable by anyone in range."
            + (" Looks like a guest SSID, but confirm it's isolated." if guessed_guest else ""),
            hosts=open_ssids,
            scope_hint="Move to WPA2/3; isolate guest WiFi onto its own VLAN."))
    if weak_ssids:
        findings.append(_finding("medium", "risk", "Weak WiFi encryption (WEP/WPA)",
            "Legacy wireless encryption that is trivially broken.",
            hosts=weak_ssids, scope_hint="Upgrade APs / re-key to WPA2-AES or WPA3."))

    # DNS zone transfer.
    dns = net.get("dns") or {}
    if dns.get("axfr_open"):
        zones = list((dns.get("axfr") or {}).keys())
        findings.append(_finding("medium", "risk", "DNS zone transfer (AXFR) allowed",
            "The DNS server hands out its entire internal zone to any client — a full map of internal hostnames and IPs.",
            hosts=zones, scope_hint="Restrict AXFR to designated secondaries."))

    # Telnet (cleartext management), especially on infrastructure.
    telnet = [f"{h.get('ipv4')} ({_name(h) or host_cat.get(h.get('ipv4'),'device')})"
              for h in hosts if 23 in _ports(h)]
    if telnet:
        on_infra = any(host_cat.get(h.get("ipv4")) in ("switch", "ap", "firewall") for h in hosts if 23 in _ports(h))
        findings.append(_finding("medium" if on_infra else "low", "risk", "Telnet (cleartext) management exposed",
            "Telnet sends credentials in plaintext. On switches/APs this means the network keys are sniffable."
            if on_infra else "Telnet is enabled — cleartext, should be disabled in favour of SSH.",
            hosts=telnet, scope_hint="Disable telnet, standardise on SSH."))

    # Default SNMP community.
    pub = [f"{d.get('ip')} ({d.get('sysname') or d.get('sysdescr') or 'device'})"
           for d in net.get("snmp_devices", []) if d.get("community_used") == "public"]
    if pub:
        findings.append(_finding("medium", "risk", "Default SNMP community ('public')",
            "Network gear answers SNMP on the default 'public' community — device config and topology are readable by anyone.",
            hosts=pub, scope_hint="Set unique SNMPv2 communities or move to SNMPv3."))

    # Legacy / EOL operating systems.
    eol = []
    for h in hosts:
        o = _os(h)
        if re.search(r"windows (xp|vista|7|server 2003|server 2008|server 2012)", o) or re.search(r"linux 2\.6", o):
            eol.append(f"{h.get('ipv4')} — {(h.get('os_guess') or {}).get('name')}")
    if eol:
        findings.append(_finding("high", "risk", "Legacy / end-of-life operating systems",
            "Unsupported OSes that no longer receive security patches — a standing liability and often a compliance blocker.",
            hosts=eol, scope_hint="Plan replacement/upgrade; isolate until then."))

    # RDP exposed on the LAN.
    rdp = [f"{h.get('ipv4')} ({_name(h) or 'host'})" for h in hosts if 3389 in _ports(h)]
    if rdp:
        findings.append(_finding("low", "risk", "RDP reachable across the LAN",
            "Remote Desktop is open to the whole flat network — a common lateral-movement path once one host is compromised.",
            hosts=rdp, scope_hint="Restrict RDP to a management VLAN / jump host."))

    # ── Opportunities (onboarding scope drivers, not strictly risks) ──
    cam_n = len(cats.get("camera", []))
    if cam_n >= 3:
        findings.append(_finding("info", "opportunity", f"{cam_n} IP cameras on site",
            "A camera fleet this size usually implies an NVR, retention storage, and bandwidth planning to manage.",
            scope_hint="Surveillance management: NVR health, storage, camera firmware."))
    net_gear = len(cats.get("switch", [])) + len(cats.get("ap", []))
    if net_gear:
        findings.append(_finding("info", "opportunity", f"{net_gear} managed network device(s)",
            "Managed switches/APs can be monitored and centrally configured — the backbone of a managed-network offering.",
            scope_hint="Network monitoring & management (SNMP/LLDP already answering)."))
    if not net.get("wan"):
        pass  # handled in narrative

    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), CAT_ORDER.get(f["kind"], 9)))
    return findings


# ── Onboarding scope worksheet ───────────────────────────────────────────────

def scope_worksheet(cats):
    """Deterministic count → suggested scope line. The AI refines wording and
    pricing; this guarantees nothing gets missed."""
    rows = []
    def add(cat, unit, note):
        n = len(cats.get(cat, []))
        if n:
            rows.append({"category": CAT_LABEL[cat], "count": n, "unit": unit, "note": note})
    add("workstation", "endpoints", "RMM agent + patching + AV per seat")
    add("server", "servers", "server monitoring, backup, patch management")
    add("hypervisor", "hosts", "hypervisor + guest VM management")
    add("nas", "appliances", "backup target / storage health")
    add("firewall", "edge", "firewall management & security policy")
    add("switch", "switches", "managed-switch monitoring")
    add("ap", "APs", "wireless management & coverage")
    add("camera", "cameras", "surveillance system management")
    add("printer", "printers", "print management (optional)")
    add("voip", "phones", "VoIP support (optional)")
    return rows


# ── Dedup ────────────────────────────────────────────────────────────────────

def dedup_hosts(hosts):
    """Same physical machine can appear on two IPs (e.g. a laptop on both a USB
    dongle and WiFi). Collapse by (hostname) when the hostname is a real,
    non-generic name, keeping the richer record and noting the extra IPs."""
    generic = {"", "unknown", "localhost", "ipad", "iphone", "android", "raspberrypi", "ubnt", "home"}
    by_name = {}
    out = []
    for h in hosts:
        key = _norm(_name(h))
        if key and key not in generic:
            if key in by_name:
                prev = by_name[key]
                prev.setdefault("_also_ips", []).append(h.get("ipv4"))
                # keep whichever has more open ports as the primary
                if len(h.get("open_ports", [])) > len(prev.get("open_ports", [])):
                    idx = out.index(prev)
                    h.setdefault("_also_ips", []).extend(prev.get("_also_ips", []))
                    h["_also_ips"].append(prev.get("ipv4"))
                    h["_also_ips"] = [ip for ip in h["_also_ips"] if ip != h.get("ipv4")]
                    out[idx] = h
                    by_name[key] = h
                continue
            by_name[key] = h
        out.append(h)
    return out


# ── Top-level ────────────────────────────────────────────────────────────────

def analyze(snapshot):
    net = snapshot.get("network", {})
    ctx = {
        "gateway_ip": (net.get("gateway") or {}).get("ipv4") or (snapshot.get("scan", {}).get("interface", {}) or {}).get("gateway"),
        "snmp_roles": {d.get("ip"): d.get("role_guess") for d in net.get("snmp_devices", [])},
    }

    hosts = dedup_hosts([dict(h) for h in snapshot.get("hosts", [])])

    cats = defaultdict(list)
    host_cat = {}
    ambiguous = []
    for h in hosts:
        cat, conf, reasons = classify(h, ctx)
        rec = {
            "ipv4": h.get("ipv4"),
            "also_ips": h.get("_also_ips", []),
            "name": _name(h),
            "vendor": h.get("vendor"),
            "os": (h.get("os_guess") or {}).get("name"),
            "ports": sorted(_ports(h)),
            "open_ports": h.get("open_ports", []),
            "mdns": h.get("mdns_services", []),
            "smb": h.get("smb"),
            "category": cat,
            "confidence": conf,
            "reasons": reasons,
        }
        cats[cat].append(rec)
        host_cat[h.get("ipv4")] = cat
        if conf == "low":
            ambiguous.append(rec)

    cats = {k: cats[k] for k, _, _ in CATEGORIES if cats.get(k)}
    findings = assess(snapshot, cats, host_cat)
    scope = scope_worksheet(cats)

    return {
        "analyzer_version": ANALYZER_VERSION,
        "scan": snapshot.get("scan", {}),
        "network": net,
        "wifi": snapshot.get("wifi", []),
        "host_count": len(hosts),
        "categories": cats,
        "category_counts": {k: len(v) for k, v in cats.items()},
        "findings": findings,
        "scope": scope,
        "ambiguous": ambiguous,
    }


def build_brief(model):
    """The compact, privacy-safe summary handed to the AI narrative layer.
    No raw packets, no per-host port dumps — just the categorized picture and
    the findings the deterministic engine already ranked."""
    scan = model["scan"]
    net = model["network"]
    return {
        "site": scan.get("site_label"),
        "location": scan.get("location"),
        "scanned_at": scan.get("finished_at") or scan.get("started_at"),
        "mode": scan.get("mode"),
        "coverage_note": scan.get("coverage_note"),
        "host_count": model["host_count"],
        "category_counts": model["category_counts"],
        "gateway": net.get("gateway"),
        "switches": [{"name": d.get("sysname"), "descr": d.get("sysdescr"),
                      "neighbors": d.get("neighbor_count")} for d in net.get("snmp_devices", [])],
        "segmented": bool(net.get("vlans_seen")),
        "wifi": [{"ssid": w.get("ssid"), "security": w.get("security"), "band": w.get("band")} for w in model["wifi"]],
        "wan": net.get("wan"),
        "findings": [{"severity": f["severity"], "kind": f["kind"], "title": f["title"],
                      "detail": f["detail"], "affected": len(f["hosts"]), "scope_hint": f["scope_hint"]}
                     for f in model["findings"]],
        "scope_worksheet": model["scope"],
        "ambiguous_devices": [{"ip": a["ipv4"], "vendor": a["vendor"], "os": a["os"],
                               "ports": a["ports"], "guess": a["category"]} for a in model["ambiguous"]],
    }


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    data = json.load(sys.stdin if src == "-" else open(src))
    m = analyze(data)
    what = sys.argv[2] if len(sys.argv) > 2 else "model"
    print(json.dumps(build_brief(m) if what == "brief" else m, indent=2, default=str))
