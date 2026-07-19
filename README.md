# Network Snapshot

A pre-sales network discovery tool. Plug a laptop into a prospect's network,
run the collector, and get one structured JSON file describing what's there —
so onboarding can be scoped (and priced) from real data instead of a walk-around.

The report side (categorization → AI narrative → pretty output) is built
separately and consumes **only** the JSON described below. That seam is what
keeps the two halves independent: the report can live in TEQhub today and move
elsewhere later without touching the collector.

## Collector

One Python file, `collect.py`. Dependency-light: it shells out to standard
tools and parses their output with the stdlib (Python 3.9+, no `pip install`).

### Install the tools (on the scanning laptop)

Debian/Ubuntu:
```bash
sudo apt install nmap arp-scan tcpdump avahi-utils network-manager lldpd
```
`lldpd` is optional but makes VLAN/switch discovery much better (it keeps an
LLDP neighbor table instead of us sniffing a few frames).

### Run

```bash
# Active scan (default) — probes with arp-scan + nmap. Needs sudo.
sudo python3 collect.py --site "Acme Dental" -o acme.json

# Passive — listen only (LLDP + mDNS + ARP/DHCP sniff) + WiFi scan.
# For sensitive sites or when an incumbent MSP is watching.
sudo python3 collect.py --passive --site "Acme Dental" -o acme.json

# No network needed — emit a realistic sample to build/test the report side.
python3 collect.py --demo -o sample-snapshot.json
```

Useful flags: `--iface eth0` (force interface), `--no-wifi`, `--listen 30`
(seconds for passive listeners), `--nmap-timeout 1800`.

### What it does

| Step | Tool | Mode | Gives |
|------|------|------|-------|
| Interface detect | `ip`/`route` | both | which NIC, IP, subnet, gateway |
| Host + MAC sweep | `arp-scan` | active | every host, MAC → vendor |
| Services / OS / shares | `nmap` (`-sV -O` + NSE) | active | open ports, OS guess, SMB shares, SNMP |
| Passive host sniff | `tcpdump` | passive | hosts from ARP/DHCP without probing |
| Switch / VLAN | `lldpctl`/`tcpdump` | both | switch name, port, VLAN (topology) |
| Service announce | `avahi-browse` | both | mDNS service types → device roles |
| WiFi survey | `nmcli` | both | SSIDs, encryption, channel, signal |

Every step is isolated — a missing tool or a failure is recorded in
`scan.steps[]` and never aborts the scan. `scan.tools_present` reports what was
available.

## The JSON contract (schema 1.0)

The whole system hinges on this shape. `hosts[]` is intentionally flat and
signal-rich so the report's rules engine can categorize (OUI vendor + open
ports + mDNS services → camera/printer/server/etc.) and the AI layer can reason
over the aggregate.

```jsonc
{
  "schema_version": "1.0",
  "scan": {
    "started_at": "ISO-8601", "finished_at": "ISO-8601",
    "duration_seconds": 560,
    "mode": "active" | "passive",
    "collector_version": "0.1.0",
    "site_label": "Acme Dental", "operator": "tzvi",
    "interface": { "name": "eth0", "mac": "..", "ipv4": "10.0.0.50",
                   "cidr": "10.0.0.0/24", "gateway": "10.0.0.1" },
    "coverage_note": "single broadcast domain … from this port; no VLAN tags seen",
    "steps": [ { "step": "nmap", "ok": true, "seconds": 512.0 } ],
    "tools_present": { "nmap": true, "arp-scan": true, "...": true }
  },

  "hosts": [
    {
      "ipv4": "10.0.0.20",
      "mac": "00:11:32:aa:bb:01",
      "vendor": "Synology",                 // from OUI — a primary role signal
      "hostname": "NAS01",
      "discovered_by": ["arp", "nmap", "mdns"],
      "os_guess": { "name": "Windows 6.1", "accuracy": 92 },
      "open_ports": [
        { "port": 445, "proto": "tcp", "service": "microsoft-ds",
          "product": "..", "version": "..", "title": "(http-title if web)" }
      ],
      "mdns_services": ["_ipp._tcp"],        // _ipp=printer, _rtsp=camera, …
      "smb": { "os": "Windows 6.1",
               "shares": [ { "name": "backups", "anonymous": true, "access": "WRITE" } ] },
      "snmp": { "sysdescr": "..", "reachable": true }
    }
  ],

  "network": {
    "subnets_seen": ["10.0.0.0/24"],
    "vlans_seen": [ { "id": 10, "source": "lldp" } ],
    "lldp_neighbors": [ { "local_port": "eth0", "switch_name": "SW-CORE",
                          "switch_port": "Gi1/0/12", "vlan": 10, "source": "lldpd" } ]
  },

  "wifi": [
    { "ssid": "Acme-Guest", "channel": 6, "band": "2.4GHz",
      "security": "OPEN", "signal": 74 }
  ]
}
```

**Field notes for the report side**
- A field is simply absent when unknown (no tool, no data) — never guess in the
  collector; that's the report/AI layer's job.
- The three role signals to key categorization off: `vendor` (OUI),
  `open_ports[].service`, and `mdns_services`. Cross-referencing them is
  deterministic and explainable.
- `coverage_note` + `network.vlans_seen` tell the report how much of the network
  a single drop actually saw — the report must be honest about this (one port =
  one broadcast domain).
- Risk flags live in the data, not pre-judged: e.g. `smb.shares[].anonymous`,
  `wifi[].security == "OPEN"`, an EOL `os_guess.name`. The rules engine surfaces
  them; the AI ranks them.

`sample-snapshot.json` (committed, also produced by `--demo`) is a realistic
example to develop the report against with no live network.

## Roadmap

- **Now:** collector + JSON contract (this repo).
- **Next:** report engine — deterministic categorization + risk flags, then an
  AI pass for the executive narrative, significance ranking, and onboarding
  scoping. Rendered as a styled HTML/PDF, attachable to a TEQhub proposal.
- **Later:** Raspberry Pi drop-box image + phone-home upload, so it can be left
  running and collected remotely.
