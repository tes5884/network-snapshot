#!/usr/bin/env python3
"""Touchscreen kiosk UI for the network-snapshot collector.

Built for a Raspberry Pi with a small (5") touchscreen and no keyboard: the
idle screen shows what the box is plugged into, and one big button runs a scan.
Stdlib only, same as the rest of the tool. Serves on localhost; a Chromium
kiosk window points at it.

    sudo python3 kiosk.py            # http://127.0.0.1:8770

Scans need root (arp-scan / nmap -O / tcpdump). Run this as root, or as a user
with passwordless sudo — it re-invokes the collector with sudo when needed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import collect  # noqa: E402  (same-directory sibling)

KIOSK_VERSION = "0.1.0"
SCAN_DIR = os.path.join(HERE, "scans")
REPORT_PATH = os.path.join(SCAN_DIR, "last-report.html")
PUBLIC_IP_TTL = 600  # seconds — one outbound call per 10 min, not per poll


def log(msg: str) -> None:
    print(f"[kiosk] {msg}", file=sys.stderr, flush=True)


# ── Network status ───────────────────────────────────────────────────────────

_ip_cache: dict = {"at": 0.0, "data": None}
_ip_lock = threading.Lock()


def internet_up(timeout: float = 1.5) -> bool:
    """A real reachability check — routes can exist with no upstream."""
    for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def public_ip_cached(online: bool) -> dict | None:
    """collect.public_ip() behind a TTL so polling doesn't hammer ipinfo."""
    if not online:
        return None
    with _ip_lock:
        fresh = time.time() - _ip_cache["at"] < PUBLIC_IP_TTL
        if fresh and _ip_cache["data"] is not None:
            return _ip_cache["data"]
    data = None
    try:
        data = collect.public_ip()
    except Exception as e:  # noqa: BLE001
        log(f"public_ip failed: {e}")
    with _ip_lock:
        # Cache failures too (briefly) so a dead lookup can't stall every poll.
        _ip_cache["at"] = time.time()
        _ip_cache["data"] = data
    return data


def link_state(iface: str | None) -> dict:
    """Carrier + speed straight from sysfs, plus SSID for wireless links."""
    out: dict = {"carrier": None, "speed_mbps": None, "ssid": None, "wireless": False}
    if not iface:
        return out
    base = f"/sys/class/net/{iface}"
    try:
        with open(f"{base}/carrier") as fh:
            out["carrier"] = fh.read().strip() == "1"
    except OSError:
        pass
    try:
        with open(f"{base}/speed") as fh:
            spd = int(fh.read().strip())
            out["speed_mbps"] = spd if spd > 0 else None
    except (OSError, ValueError):
        pass
    out["wireless"] = os.path.isdir(f"{base}/wireless") or os.path.isdir(f"{base}/phy80211")
    if out["wireless"] and collect.have("iw"):
        rc, txt, _ = collect.run(["iw", "dev", iface, "link"], 4)
        if rc == 0:
            m = re.search(r"SSID:\s*(.+)", txt)
            if m:
                out["ssid"] = m.group(1).strip()
    return out


def monitor_ifaces(uplink: str | None = None) -> list[str]:
    """Wireless adapters that can actually do monitor mode (the Alfa), so the UI
    only offers the survey when the gear is plugged in. Monitor support is a
    property of the *phy*, not the netdev, so resolve each interface's phy and
    read its supported modes. The interface carrying the default route is
    excluded — capturing on the uplink would drop the box off the network."""
    if not collect.have("iw"):
        return []
    found = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    for name in names:
        if name == "lo" or name == uplink:
            continue
        try:
            with open(f"/sys/class/net/{name}/phy80211/name") as fh:
                phy = fh.read().strip()
        except OSError:
            continue  # not a wireless device
        rc, txt, _ = collect.run(["iw", "phy", phy, "info"], 6)
        if rc != 0:
            continue
        modes = re.search(r"Supported interface modes:\s*((?:\s*\*\s*\S+\n?)+)", txt)
        if modes and re.search(r"\*\s*monitor", modes.group(1)):
            found.append(name)
    return found


def submit_target() -> str | None:
    """Where finished scans upload to, if auto-submit is configured."""
    conf_path = os.path.join(HERE, "submit.conf")
    if not os.path.exists(conf_path):
        return None
    try:
        with open(conf_path) as fh:
            return (json.load(fh) or {}).get("url")
    except (ValueError, OSError):
        return None


def status_payload() -> dict:
    iface_info = collect.detect_interface(None)
    online = internet_up()
    wan = public_ip_cached(online) or {}
    return {
        "hostname": socket.gethostname(),
        "time": datetime.now().strftime("%-I:%M %p"),
        "online": online,
        "iface": iface_info.get("name"),
        "ipv4": iface_info.get("ipv4"),
        "cidr": iface_info.get("cidr"),
        "gateway": iface_info.get("gateway"),
        "mac": iface_info.get("mac"),
        "link": link_state(iface_info.get("name")),
        "public_ip": wan.get("public_ip"),
        "isp": wan.get("isp"),
        "geo": wan.get("geo"),
        "monitor_ifaces": monitor_ifaces(iface_info.get("name")),
        "submit_url": submit_target(),
        "collector_version": collect.COLLECTOR_VERSION,
        "kiosk_version": KIOSK_VERSION,
    }


# ── Scan job ─────────────────────────────────────────────────────────────────

class ScanJob:
    """One running collector process, its live log, and its result."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.state = "idle"  # idle | running | done | failed | cancelled
        self.started: float | None = None
        self.finished: float | None = None
        self.line = ""
        self.log: list[str] = []
        self.result: dict | None = None
        self.error: str | None = None
        self.snapshot_path: str | None = None
        self.report_ready = False
        self.mode = "active"

    def snapshot(self) -> dict:
        with self.lock:
            elapsed = None
            if self.started:
                elapsed = round((self.finished or time.time()) - self.started, 1)
            return {
                "state": self.state,
                "mode": self.mode,
                "elapsed": elapsed,
                "line": self.line,
                "log": self.log[-40:],
                "result": self.result,
                "error": self.error,
                "report_ready": self.report_ready,
            }

    def start(self, params: dict) -> tuple[bool, str]:
        with self.lock:
            if self.state == "running":
                return False, "a scan is already running"
            self.state = "running"
            self.mode = "passive" if params.get("mode") == "passive" else "active"
            self.started = time.time()
            self.finished = None
            self.line = "starting…"
            self.log = []
            self.result = None
            self.error = None
            self.report_ready = False
        threading.Thread(target=self._run, args=(params,), daemon=True).start()
        return True, "started"

    def _argv(self, params: dict, outfile: str) -> list[str]:
        argv = [sys.executable, os.path.join(HERE, "collect.py"),
                "-o", outfile, "--skip-check", "--no-update"]
        if params.get("mode") == "passive":
            argv.append("--passive")
        if params.get("site"):
            argv += ["--site", str(params["site"])]
        if params.get("speedtest"):
            argv.append("--speedtest")
        if params.get("wifi_monitor"):
            argv += ["--wifi-monitor", str(params["wifi_monitor"])]
            # Pin the uplink: flipping an adapter into monitor mode can confuse
            # route-based auto-detection mid-scan.
            uplink = collect.detect_interface(None).get("name")
            if uplink and uplink != params["wifi_monitor"]:
                argv += ["--iface", str(uplink)]
        if os.geteuid() != 0:
            argv = ["sudo", "-n"] + argv
        return argv

    def _run(self, params: dict) -> None:
        os.makedirs(SCAN_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        outfile = os.path.join(SCAN_DIR, f"snapshot-{stamp}.json")
        argv = self._argv(params, outfile)
        log(f"scan: {' '.join(argv)}")
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as e:
            with self.lock:
                self.state, self.error = "failed", f"could not start collector: {e}"
                self.finished = time.time()
            return

        with self.lock:
            self.proc = proc

        for raw in proc.stderr:  # type: ignore[union-attr]
            line = raw.rstrip()
            if not line:
                continue
            pretty = line.split("] ", 1)[1] if line.startswith("[snapshot] ") else line
            with self.lock:
                self.line = pretty
                self.log.append(pretty)
        rc = proc.wait()

        with self.lock:
            self.finished = time.time()
            self.proc = None
            if self.state == "cancelled":
                return
            if rc != 0:
                self.state = "failed"
                self.error = self.line or f"collector exited {rc}"
                return

        try:
            summary = summarize(outfile)
        except Exception as e:  # noqa: BLE001
            with self.lock:
                self.state, self.error = "failed", f"scan finished but analysis failed: {e}"
            return

        with self.lock:
            # The collector writes the file before uploading and never stamps the
            # result, so its log is the only truthful upload signal.
            summary["submitted"] = any(l.startswith("submitted →") for l in self.log)
            summary["submit_failed"] = any(l.startswith("submit FAILED") for l in self.log)
            self.state = "done"
            self.result = summary
            self.snapshot_path = outfile
        threading.Thread(target=self._render_report, args=(outfile,), daemon=True).start()

    def _render_report(self, outfile: str) -> None:
        try:
            subprocess.run(
                [sys.executable, os.path.join(HERE, "report.py"), outfile, "-o", REPORT_PATH],
                capture_output=True, text=True, timeout=180, check=True,
            )
            with self.lock:
                self.report_ready = True
        except (subprocess.SubprocessError, OSError) as e:
            log(f"report render failed: {e}")

    def cancel(self) -> bool:
        with self.lock:
            proc, running = self.proc, self.state == "running"
            if running:
                self.state = "cancelled"
                self.line = "cancelled"
        if not running:
            return False
        if proc is not None:
            try:
                # The collector shells out to nmap/tcpdump — kill the whole group.
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                pass
        return True


_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def summarize(snapshot_path: str) -> dict:
    """Post-scan headline numbers, straight from the shared analyzer."""
    import analyze  # local import: only needed once a scan finishes

    with open(snapshot_path) as fh:
        snap = json.load(fh)
    model = analyze.analyze(snap)
    findings = model.get("findings", [])
    sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f.get("severity", "low")] = sev.get(f.get("severity", "low"), 0) + 1
    cats = model.get("category_counts", {}) or {}
    top = sorted(cats.items(), key=lambda kv: -kv[1])[:6]
    return {
        "hosts": model.get("host_count", 0),
        "severity": sev,
        "categories": [{"name": k, "count": v} for k, v in top],
        "site": (model.get("scan") or {}).get("site_label"),
        # Top findings by severity rather than high-only: a clean scan would
        # otherwise show an empty panel and tell the operator nothing.
        "headline": [{"severity": f.get("severity"), "title": f.get("title")}
                     for f in sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))][:4],
        "file": os.path.basename(snapshot_path),
        "submitted": False,   # set by the caller from the collector's log
    }


JOB = ScanJob()


# ── Power ────────────────────────────────────────────────────────────────────

def power_action(what: str) -> bool:
    cmd = {"reboot": ["systemctl", "reboot"], "poweroff": ["systemctl", "poweroff"]}.get(what)
    if not cmd:
        return False
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        subprocess.Popen(cmd)
        return True
    except OSError:
        return False


# ── HTTP ─────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = f"netsnapshot-kiosk/{KIOSK_VERSION}"

    def log_message(self, fmt, *args):  # quiet — the scan log is the signal
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/status":
            self._json(status_payload())
        elif path == "/api/scan":
            self._json(JOB.snapshot())
        elif path == "/report":
            # Kiosk mode has no browser chrome, so a bare report page would be a
            # dead end. Wrap it with a back bar and iframe the real thing.
            if not os.path.exists(REPORT_PATH):
                self._send(404, b"no report yet", "text/plain")
                return
            self._send(200, REPORT_SHELL.encode(), "text/html; charset=utf-8")
        elif path == "/report/raw":
            if not os.path.exists(REPORT_PATH):
                self._send(404, b"no report yet", "text/plain")
                return
            with open(REPORT_PATH, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}

        if path == "/api/scan":
            ok, msg = JOB.start(body if isinstance(body, dict) else {})
            self._json({"ok": ok, "message": msg}, 200 if ok else 409)
        elif path == "/api/scan/cancel":
            self._json({"ok": JOB.cancel()})
        elif path == "/api/power":
            self._json({"ok": power_action(str(body.get("action", "")))})
        else:
            self._send(404, b"not found", "text/plain")


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
<title>Network Snapshot</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c232c; --line:#2a323d;
    --tx:#e8edf3; --dim:#8b98a8;
    --ok:#2ea043; --warn:#d29922; --bad:#da3633; --acc:#2f81f7;
    --tap:88px;
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{margin:0;height:100%;overflow:hidden}
  body{
    background:var(--bg); color:var(--tx);
    font:16px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    user-select:none; touch-action:manipulation;
  }
  .screen{position:absolute;inset:0;display:none;flex-direction:column;padding:14px;gap:12px}
  .screen.on{display:flex}

  header{display:flex;align-items:center;gap:12px;flex:0 0 auto}
  .host{font-size:22px;font-weight:700;letter-spacing:.3px}
  .pill{
    display:inline-flex;align-items:center;gap:8px;padding:7px 14px;border-radius:999px;
    font-size:15px;font-weight:600;background:var(--panel2);border:1px solid var(--line)
  }
  .dot{width:11px;height:11px;border-radius:50%;background:var(--dim);flex:0 0 auto}
  .dot.up{background:var(--ok);box-shadow:0 0 9px var(--ok)}
  .dot.down{background:var(--bad)}
  .spacer{flex:1}
  .clock{font-size:19px;color:var(--dim);font-variant-numeric:tabular-nums}
  .iconbtn{
    width:52px;height:52px;border-radius:14px;border:1px solid var(--line);
    background:var(--panel2);color:var(--dim);font-size:22px;line-height:1
  }

  .body{flex:1;display:flex;gap:12px;min-height:0}
  .col{display:flex;flex-direction:column;gap:12px;min-height:0}
  .col.info{flex:1.15}
  .col.act{flex:1}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:14px}
  .card h2{margin:0 0 10px;font-size:13px;letter-spacing:1.4px;text-transform:uppercase;color:var(--dim);font-weight:700}
  /* Fill the panel height instead of leaving dead space under the cards —
     it also spreads the rows out, which reads better at arm's length. */
  .col.info .card{flex:1;display:flex;flex-direction:column}
  .col.info .card .kv{flex:1;align-items:center}

  .kv{display:flex;justify-content:space-between;align-items:baseline;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
  .kv:last-child{border-bottom:0}
  .kv .k{color:var(--dim);font-size:15px;flex:0 0 auto}
  .kv .v{font-size:19px;font-weight:600;font-variant-numeric:tabular-nums;text-align:right;
        overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .v.mono{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:18px}
  .v.sm{font-size:16px;font-weight:500;white-space:normal;text-align:right}

  button{font-family:inherit;cursor:pointer}
  .big{
    width:100%;min-height:var(--tap);border:0;border-radius:18px;
    background:var(--acc);color:#fff;font-size:27px;font-weight:800;letter-spacing:.4px;
    display:flex;align-items:center;justify-content:center;gap:12px
  }
  #btn-scan{flex:1;font-size:38px}   /* the one thing you tap — give it the room */
  .big:active{transform:scale(.98)}
  .big.ghost{background:var(--panel2);color:var(--tx);border:1px solid var(--line);font-size:21px;font-weight:700;min-height:68px}
  .big.danger{background:var(--bad)}
  .big[disabled]{opacity:.45}

  .opts{display:flex;gap:10px;flex:0 0 auto}
  .chip{
    flex:1;min-height:78px;border-radius:14px;border:1px solid var(--line);
    background:var(--panel2);color:var(--dim);font-size:16px;font-weight:700;
    display:flex;align-items:center;justify-content:center;gap:8px;padding:0 8px;text-align:center
  }
  .chip.on{background:rgba(47,129,247,.16);border-color:var(--acc);color:#cfe3ff}
  .chip[disabled]{opacity:.35}

  /* scanning */
  .runwrap{flex:1;display:flex;flex-direction:column;justify-content:center;align-items:center;gap:18px;min-height:0}
  .ring{width:104px;height:104px;border-radius:50%;border:9px solid var(--panel2);border-top-color:var(--acc);animation:spin 1.05s linear infinite;flex:0 0 auto}
  @keyframes spin{to{transform:rotate(360deg)}}
  .elapsed{font-size:46px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1}
  .step{font-size:20px;color:var(--tx);text-align:center;padding:0 16px;min-height:28px}
  .hint{font-size:15px;color:var(--dim);text-align:center;padding:0 20px}
  .tail{
    width:100%;max-height:118px;overflow:hidden;background:var(--panel);border:1px solid var(--line);
    border-radius:12px;padding:9px 12px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;
    color:var(--dim);line-height:1.55;display:flex;flex-direction:column-reverse
  }

  /* result */
  .stats{display:flex;gap:10px}
  .stat{flex:1;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:12px 8px;text-align:center}
  .stat .n{font-size:40px;font-weight:800;line-height:1.05;font-variant-numeric:tabular-nums}
  .stat .l{font-size:12.5px;color:var(--dim);text-transform:uppercase;letter-spacing:1.1px;margin-top:3px}
  .n.bad{color:var(--bad)} .n.warn{color:var(--warn)} .n.ok{color:var(--ok)}
  .cats{display:flex;flex-wrap:wrap;gap:7px}
  .cat{background:var(--panel2);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:15px}
  .cat b{color:var(--acc)}
  .flags{margin:0;padding:0;list-style:none;font-size:16px;line-height:1.5}
  .flags li{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
  .flags li:last-child{border-bottom:0}
  .sev{
    flex:0 0 auto;min-width:64px;text-align:center;border-radius:6px;padding:3px 8px;
    font-size:11.5px;font-weight:800;text-transform:uppercase;letter-spacing:.7px
  }
  .sev.high{background:rgba(218,54,51,.2);color:#ff8a84}
  .sev.medium{background:rgba(210,153,34,.18);color:#e3b341}
  .sev.low,.sev.info{background:var(--panel2);color:var(--dim)}
  .banner{border-radius:12px;padding:10px 13px;font-size:15px;font-weight:600}
  .banner.ok{background:rgba(46,160,67,.15);color:#7ee092;border:1px solid rgba(46,160,67,.4)}
  .banner.warn{background:rgba(210,153,34,.13);color:#e3b341;border:1px solid rgba(210,153,34,.4)}
  .banner.bad{background:rgba(218,54,51,.14);color:#ff8a84;border:1px solid rgba(218,54,51,.4)}
  .scroll{overflow-y:auto;-webkit-overflow-scrolling:touch}
  .rowbtns{display:flex;gap:10px}
  .rowbtns .big{flex:1}

  /* modal */
  .modal{position:absolute;inset:0;background:rgba(0,0,0,.72);display:none;align-items:center;justify-content:center;padding:22px;z-index:9}
  .modal.on{display:flex}
  .sheet{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:20px;width:min(460px,100%);display:flex;flex-direction:column;gap:12px}
  .sheet h3{margin:0;font-size:21px}
</style>
</head>
<body>

<!-- ── IDLE ─────────────────────────────────────────────────────────── -->
<div class="screen on" id="s-idle">
  <header>
    <span class="host" id="hostname">—</span>
    <span class="pill"><i class="dot" id="netdot"></i><span id="netlabel">checking…</span></span>
    <span class="spacer"></span>
    <span class="clock" id="clock">—</span>
    <button class="iconbtn" id="powerbtn">⏻</button>
  </header>

  <div class="body">
    <div class="col info">
      <div class="card">
        <h2>This network</h2>
        <div class="kv"><span class="k">Interface</span><span class="v mono" id="k-iface">—</span></div>
        <div class="kv"><span class="k">IP address</span><span class="v mono" id="k-ip">—</span></div>
        <div class="kv"><span class="k">Subnet</span><span class="v mono" id="k-cidr">—</span></div>
        <div class="kv"><span class="k">Gateway</span><span class="v mono" id="k-gw">—</span></div>
        <div class="kv"><span class="k">Link</span><span class="v" id="k-link">—</span></div>
      </div>
      <div class="card">
        <h2>Internet</h2>
        <div class="kv"><span class="k">Public IP</span><span class="v mono" id="k-pub">—</span></div>
        <div class="kv"><span class="k">Provider</span><span class="v sm" id="k-isp">—</span></div>
        <div class="kv"><span class="k">Location</span><span class="v sm" id="k-loc">—</span></div>
      </div>
    </div>

    <div class="col act">
      <button class="big" id="btn-scan">▶ START SCAN</button>
      <div class="opts">
        <button class="chip" id="opt-passive">Passive<br>only</button>
        <button class="chip" id="opt-speed">Speed<br>test</button>
        <button class="chip" id="opt-mon">WiFi<br>survey</button>
      </div>
      <div class="hint" id="uploadhint">&nbsp;</div>
    </div>
  </div>
</div>

<!-- ── RUNNING ──────────────────────────────────────────────────────── -->
<div class="screen" id="s-run">
  <header>
    <span class="host">Scanning…</span>
    <span class="spacer"></span>
    <span class="clock" id="run-mode">active</span>
  </header>
  <div class="runwrap">
    <div class="ring"></div>
    <div class="elapsed" id="run-elapsed">0:00</div>
    <div class="step" id="run-step">starting…</div>
    <div class="hint">The nmap phase is the slow part — a few minutes is normal.</div>
    <div class="tail" id="run-tail"></div>
  </div>
  <button class="big ghost" id="btn-cancel">✕ Cancel scan</button>
</div>

<!-- ── RESULT ───────────────────────────────────────────────────────── -->
<div class="screen" id="s-done">
  <header>
    <span class="host" id="done-title">Scan complete</span>
    <span class="spacer"></span>
    <span class="clock" id="done-time">—</span>
  </header>
  <div class="scroll" style="flex:1;display:flex;flex-direction:column;gap:12px">
    <div class="stats">
      <div class="stat"><div class="n ok" id="r-hosts">0</div><div class="l">Devices</div></div>
      <div class="stat"><div class="n bad" id="r-high">0</div><div class="l">High</div></div>
      <div class="stat"><div class="n warn" id="r-med">0</div><div class="l">Medium</div></div>
      <div class="stat"><div class="n" id="r-mins">—</div><div class="l">Minutes</div></div>
    </div>
    <div class="banner" id="r-upload"></div>
    <div class="card" id="r-flagcard">
      <h2>Findings</h2>
      <ul class="flags" id="r-flags"></ul>
    </div>
    <div class="card">
      <h2>What's out there</h2>
      <div class="cats" id="r-cats"></div>
    </div>
  </div>
  <div class="rowbtns">
    <button class="big ghost" id="btn-report">View report</button>
    <button class="big" id="btn-done">✓ Done</button>
  </div>
</div>

<!-- ── FAILED ───────────────────────────────────────────────────────── -->
<div class="screen" id="s-fail">
  <header><span class="host">Scan failed</span></header>
  <div class="runwrap">
    <div style="font-size:66px;color:var(--bad)">!</div>
    <div class="step" id="fail-msg">—</div>
  </div>
  <div class="rowbtns">
    <button class="big ghost" id="btn-failback">← Back</button>
    <button class="big" id="btn-retry">↻ Try again</button>
  </div>
</div>

<!-- ── POWER ────────────────────────────────────────────────────────── -->
<div class="modal" id="m-power">
  <div class="sheet">
    <h3>Power</h3>
    <button class="big ghost" id="btn-reboot">↻ Restart</button>
    <button class="big danger" id="btn-off">⏻ Shut down</button>
    <button class="big ghost" id="btn-pcancel">Cancel</button>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const opts = {passive:false, speedtest:false, monitor:null};
let monIface = null, lastState = "idle", busy = false;

function show(name){
  for (const s of document.querySelectorAll(".screen")) s.classList.toggle("on", s.id === "s-"+name);
}
function mmss(sec){
  sec = Math.max(0, Math.round(sec||0));
  return Math.floor(sec/60) + ":" + String(sec%60).padStart(2,"0");
}
const dash = v => (v === null || v === undefined || v === "") ? "—" : v;

async function poll(){
  try{
    const st = await (await fetch("/api/status")).json();
    $("hostname").textContent = st.hostname;
    $("clock").textContent = st.time;
    const up = st.online;
    $("netdot").className = "dot " + (up ? "up" : "down");
    let label = up ? "Online" : "No internet";
    if (st.link && st.link.carrier === false) label = "Cable unplugged";
    $("netlabel").textContent = label;

    $("k-iface").textContent = dash(st.iface);
    $("k-ip").textContent    = dash(st.ipv4);
    $("k-cidr").textContent  = dash(st.cidr);
    $("k-gw").textContent    = dash(st.gateway);
    $("k-pub").textContent   = dash(st.public_ip);
    $("k-isp").textContent   = dash(st.isp);
    $("k-loc").textContent   = dash(st.geo);
    // An empty row is just wasted panel on a 5" screen — drop it until it fills.
    $("k-loc").parentElement.style.display = st.geo ? "" : "none";

    const lk = st.link || {};
    let linktxt = "—";
    if (lk.carrier === false) linktxt = "unplugged";
    else if (lk.ssid) linktxt = "WiFi · " + lk.ssid;
    else if (lk.speed_mbps) linktxt = (lk.speed_mbps >= 1000 ? (lk.speed_mbps/1000)+" Gb" : lk.speed_mbps+" Mb") + " wired";
    else if (lk.carrier) linktxt = "connected";
    $("k-link").textContent = linktxt;

    monIface = (st.monitor_ifaces && st.monitor_ifaces[0]) || null;
    $("opt-mon").disabled = !monIface;
    if (!monIface){ opts.monitor = null; $("opt-mon").classList.remove("on"); }
    $("uploadhint").textContent = st.submit_url
      ? "Scans upload automatically" : "Saved on this device (upload not set up)";
    $("btn-scan").disabled = !st.iface;
  }catch(e){ /* server restarting — the next tick recovers */ }
}

async function pollScan(){
  let j;
  try{ j = await (await fetch("/api/scan")).json(); }catch(e){ return; }
  if (j.state === "running"){
    if (lastState !== "running") show("run");
    $("run-mode").textContent = j.mode || "active";
    $("run-elapsed").textContent = mmss(j.elapsed);
    $("run-step").textContent = j.line || "working…";
    $("run-tail").innerHTML = (j.log||[]).slice(-6).reverse()
      .map(l => "<div>"+l.replace(/[<&]/g, c => c === "<" ? "&lt;" : "&amp;")+"</div>").join("");
  } else if (j.state === "done"){
    if (lastState !== "done"){ renderResult(j); show("done"); }
    // The report renders in the background after the scan finishes, so keep
    // re-checking — on transition alone the button would stay disabled forever.
    $("btn-report").disabled = !j.report_ready;
  } else if ((j.state === "failed" || j.state === "cancelled") && lastState !== j.state){
    if (j.state === "failed"){ $("fail-msg").textContent = j.error || "unknown error"; show("fail"); }
    else show("idle");
  }
  lastState = j.state;
}

function renderResult(j){
  const r = j.result || {};
  const sev = r.severity || {};
  $("r-hosts").textContent = r.hosts || 0;
  $("r-high").textContent  = sev.high || 0;
  $("r-med").textContent   = sev.medium || 0;
  $("r-mins").textContent  = j.elapsed ? Math.max(1, Math.round(j.elapsed/60)) : "—";
  $("done-title").textContent = r.site ? ("Scan complete · " + r.site) : "Scan complete";
  $("done-time").textContent = new Date().toLocaleTimeString([], {hour:"numeric", minute:"2-digit"});

  const up = $("r-upload");
  if (r.submitted){ up.className = "banner ok"; up.textContent = "✓ Uploaded to TEQhub — assign it to a client there"; }
  else if (r.submit_failed){ up.className = "banner bad"; up.textContent = "Upload failed — saved here: " + (r.file || "snapshot.json"); }
  else { up.className = "banner warn"; up.textContent = "Saved on this device: " + (r.file || "snapshot.json"); }

  const flags = r.headline || [];
  $("r-flagcard").style.display = flags.length ? "" : "none";
  $("r-flags").innerHTML = flags.map(f =>
    '<li><span class="sev '+(f.severity||"low")+'">'+(f.severity||"low")+'</span>'+f.title+'</li>').join("");
  $("r-cats").innerHTML = (r.categories||[])
    .map(c => '<span class="cat"><b>'+c.count+'</b> '+c.name+'</span>').join("");
  $("btn-report").disabled = !j.report_ready;
}

function toggle(btn, key){
  btn.addEventListener("click", () => {
    if (btn.disabled) return;
    if (key === "monitor"){ opts.monitor = opts.monitor ? null : monIface; btn.classList.toggle("on", !!opts.monitor); return; }
    opts[key] = !opts[key];
    btn.classList.toggle("on", opts[key]);
  });
}
toggle($("opt-passive"), "passive");
toggle($("opt-speed"), "speedtest");
toggle($("opt-mon"), "monitor");

async function startScan(){
  if (busy) return; busy = true;
  $("run-step").textContent = "starting…";
  $("run-tail").innerHTML = "";
  show("run");
  try{
    await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({mode: opts.passive ? "passive" : "active",
                            speedtest: opts.speedtest, wifi_monitor: opts.monitor})});
  }catch(e){}
  busy = false;
}
$("btn-scan").addEventListener("click", startScan);
$("btn-retry").addEventListener("click", startScan);
$("btn-cancel").addEventListener("click", async () => {
  await fetch("/api/scan/cancel", {method:"POST"}); show("idle");
});
$("btn-done").addEventListener("click", () => show("idle"));
$("btn-failback").addEventListener("click", () => show("idle"));
$("btn-report").addEventListener("click", () => { location.href = "/report"; });

$("powerbtn").addEventListener("click", () => $("m-power").classList.add("on"));
$("btn-pcancel").addEventListener("click", () => $("m-power").classList.remove("on"));
$("btn-reboot").addEventListener("click", () => fetch("/api/power",{method:"POST",
  headers:{"Content-Type":"application/json"}, body:'{"action":"reboot"}'}));
$("btn-off").addEventListener("click", () => fetch("/api/power",{method:"POST",
  headers:{"Content-Type":"application/json"}, body:'{"action":"poweroff"}'}));

poll(); pollScan();
setInterval(poll, 5000);
setInterval(pollScan, 1000);
</script>
</body>
</html>
"""


REPORT_SHELL = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Report</title>
<style>
  html,body{margin:0;height:100%;background:#0d1117;overflow:hidden}
  .bar{
    height:64px;display:flex;align-items:center;gap:14px;padding:0 14px;
    background:#161b22;border-bottom:1px solid #2a323d;
    font:600 19px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#e8edf3
  }
  .bar button{
    min-height:46px;padding:0 20px;border-radius:12px;border:1px solid #2a323d;
    background:#1c232c;color:#e8edf3;font:700 18px system-ui,sans-serif
  }
  iframe{width:100%;height:calc(100% - 64px);border:0;background:#fff}
</style>
</head>
<body>
  <div class="bar"><button onclick="location.href='/'">← Back</button><span>Scan report</span></div>
  <iframe src="/report/raw"></iframe>
</body>
</html>
"""


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Touchscreen kiosk for network-snapshot")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8770)
    args = ap.parse_args()

    os.makedirs(SCAN_DIR, exist_ok=True)
    if os.geteuid() != 0 and not shutil.which("sudo"):
        log("warning: not root and no sudo — scans will fail")

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    log(f"kiosk v{KIOSK_VERSION} on http://{args.host}:{args.port}  (collector v{collect.COLLECTOR_VERSION})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("bye")
    return 0


if __name__ == "__main__":
    sys.exit(main())
