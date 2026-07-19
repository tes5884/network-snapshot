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
sudo apt install nmap arp-scan tcpdump avahi-utils network-manager lldpd snmp aircrack-ng
```
`lldpd` is optional but makes VLAN/switch discovery much better (it keeps an
LLDP neighbor table instead of us sniffing a few frames).

Or just let the collector check for you and install what's missing:
```bash
sudo python3 collect.py --check      # report + offer to apt-install missing tools
```
The preflight also runs automatically before every scan (skip with `--skip-check`,
auto-install with `--yes`).

### Run — the easy way (TUI)

Don't want to remember flags? Launch the terminal UI, fill in the fields, hit
Run:

```bash
sudo python3 run.py
```

Arrow keys move, Enter edits a field / selects an action, Space toggles, Left/
Right switch the mode. Every collector option is exposed (site, drop location,
operator, active/passive, interface, WiFi on/off, listen seconds, nmap cap,
output file). If curses can't start (no TTY), it falls back to a plain
question-and-answer wizard automatically. It just assembles and runs
`collect.py` — nothing you can't also do by hand below.

### Run — by hand (flags)

```bash
# Active scan (default) — probes with arp-scan + nmap. Needs sudo.
sudo python3 collect.py --site "Acme Dental" --location "reception jack" -o acme.json

# Passive — listen only (LLDP + mDNS + ARP/DHCP sniff) + WiFi scan.
# For sensitive sites or when an incumbent MSP is watching.
sudo python3 collect.py --passive --site "Acme Dental" -o acme.json

# No network needed — emit a realistic sample to build/test the report side.
python3 collect.py --demo -o sample-snapshot.json
```

Useful flags: `--iface eth0` (force interface), `--no-wifi`, `--listen 30`
(seconds for passive listeners), `--nmap-timeout 1800`.

### Auto-submit

After scanning, the collector POSTs the snapshot to a webhook — the local file
is always written first, so a failed upload never loses a scan. It targets, in
order: `--submit` flag → `SNAPSHOT_SUBMIT_URL` env → a `submit.conf` next to the
script. **The config file is what makes it automatic in the field:** `sudo`
strips env vars, but a file survives, so once `submit.conf` exists every scan
uploads with no flag.

```bash
cp submit.conf.example submit.conf   # then paste the intake secret
sudo python3 collect.py --site "Acme Dental" -o acme.json   # auto-uploads
sudo python3 collect.py --site "Acme Dental" --no-submit    # opt out for one run
```

`submit.conf` (gitignored — it holds the secret):
```json
{ "url": "https://hub.teqbytes.com/api/network-snapshots/intake", "secret": "<intake secret>" }
```

The default target is **TEQhub's intake endpoint** (`POST /network-snapshots/
intake`, secured with an `x-snapshot-secret` header): it analyzes the snapshot,
auto-matches it to a company by site label, and files it (unmatched scans land
"unassigned" for the operator to assign in the UI). The collector doesn't know
or care where it lands — repoint the URL and it hits anything that speaks the
same POST.

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
| DNS recon | `dig` | active | reverse-DNS host names + AXFR zone dump (full inventory if the DNS server allows it) |
| NetBIOS | `nbtscan` | active | Windows names + workgroup/domain |
| SNMP discovery | `onesixtyone` | active | every SNMP responder + working community → feeds topology |
| Public/WAN IP | `urllib` (ipinfo) | both | the site's public IP + ISP/org — one outbound request, doesn't touch the LAN |
| WAN speed | `speedtest-cli` | opt-in `--speedtest` | download/upload/ping of the internet circuit |

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

## Report engine

Two files, still stdlib-only, that consume the JSON above and nothing else:

- **`analyze.py`** — the deterministic engine (~80%). Snapshot in, structured
  *findings model* out: each host categorized (firewall / switch / AP / server /
  NAS / hypervisor / workstation / camera / printer / VoIP / mobile / IoT /
  unclassified) by cross-referencing OUI vendor + open ports + mDNS services +
  SNMP role, each with a confidence (`low` = the ambiguous ~20% for the AI to
  refine). It ranks risk/opportunity flags (flat network, anonymous SMB shares,
  open/weak WiFi, AXFR, telnet, default SNMP community, EOL OS, exposed RDP…)
  and builds an onboarding-scope worksheet (count → managed-service line). Hosts
  seen on two IPs (laptop on dongle + WiFi) are deduped by hostname.
- **`report.py`** — renders that model into a **self-contained, print-to-PDF
  HTML report**: masthead, KPI band, ranked findings with severity chips and
  onboarding implications, device inventory grouped by category, an SNMP/LLDP
  topology diagram, wireless survey, WAN circuit, and the scope worksheet.

```bash
python3 report.py acme.json -o acme-report.html          # deterministic report
python3 report.py acme.json --brief brief.json           # emit the AI-input JSON only
python3 report.py acme.json -o acme-report.html \
        --narrative summary.md                           # drop in an AI exec summary
```

The **AI seam** is `build_brief()`: a compact, privacy-safe summary (categories,
findings, scope — never raw packets or per-host port dumps) that the narrative
layer reads to write the executive summary, rank significance, and resolve the
ambiguous devices. Its output comes back as a markdown file fed to `--narrative`;
with no narrative supplied, a deterministic auto-summary fills the slot so the
report is always complete. This keeps the AI decoupled — it can run in TEQhub,
n8n, or anywhere, and the report engine never depends on it. `sample-report.html`
(committed) is an example built from the demo data.

## Roadmap

- **Now:** collector + JSON contract + report engine (this repo).
- **Next:** wire the AI narrative pass (brief → executive summary/ranking/
  scoping) into TEQhub or n8n, and a one-shot `--pdf` via headless Chromium.
- **Monitor-mode WiFi** (built, untested until the Alfa card arrives): pass
  `--wifi-monitor wlan1` for a passive full-RF survey — per-AP client counts,
  hidden SSIDs, channel congestion — instead of the basic managed scan. Needs a
  monitor-capable adapter (Alfa AWUS036ACH/ACM) on native Linux. Passive only;
  never injects.
- **SNMP topology** (built): always runs — walks the gateway + any SNMP-
  responsive network gear (LLDP-MIB neighbor table, IF-MIB, system identity) to
  reconstruct the diagram: `network.gateway` (router/firewall identity),
  `network.snmp_devices[]` (each switch/AP with its LLDP neighbors + port), and
  `network.topology_edges[]` (the adjacency the report renders as a graph).
  Read-only; tries `--snmp-community` (default `public`). No SNMP response →
  empty topology, everything else still collected. The full cable-level map
  needs SNMP on the switches — passive-only yields just the gateway + immediate
  LLDP neighbor.
- **Later:** Raspberry Pi drop-box image + phone-home upload, so it can be left
  running and collected remotely.
