#!/usr/bin/env python3
"""
Field scanner agent
===================

Turns a headless Raspberry Pi into a phone-dispatched drop-box. It self-enrolls
with TEQhub, heartbeats the network it's plugged into, polls for scan jobs, runs
the collector, and posts the snapshot back — no keyboard/monitor on the Pi, you
drive it from the phone.

Runs as a systemd service on boot (see setup-pi.sh). Stdlib only.

    agent.conf (next to this file):   {"teqhub_url": "...", "enroll_secret": "..."}
    agent-identity.json (generated):  {"device_id": "...", "token": "..."}
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONF_FILE = HERE / "agent.conf"
IDENT_FILE = HERE / "agent-identity.json"
COLLECT = HERE / "collect.py"

HEARTBEAT_EVERY = 20      # seconds
IDLE_POLL = 5             # seconds between job polls when idle
UPDATE_EVERY = 1800       # seconds between idle self-update checks (git pull)


def log(msg):
    print(f"[agent] {msg}", flush=True)


def load_conf():
    if not CONF_FILE.exists():
        sys.exit("agent.conf missing — copy agent.conf.example and fill it in")
    return json.loads(CONF_FILE.read_text())


def identity():
    if IDENT_FILE.exists():
        return json.loads(IDENT_FILE.read_text())
    ident = {"device_id": "pi-" + secrets.token_hex(6), "token": secrets.token_hex(24)}
    IDENT_FILE.write_text(json.dumps(ident))
    log(f"generated device identity {ident['device_id']}")
    return ident


def _req(conf, ident, method, path, body=None, headers=None, timeout=120):
    url = conf["teqhub_url"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if ident:
        req.add_header("X-Scanner-Id", ident["device_id"])
        req.add_header("X-Scanner-Token", ident["token"])
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        txt = r.read().decode()
        return r.status, (json.loads(txt) if txt else {})


def self_update():
    """Keep the Pi current: git-pull the repo, install any newly-needed tools,
    and restart if the code changed. Called on startup and periodically while
    idle so a field Pi always runs the latest checks without a visit."""
    here = str(HERE)
    if not os.path.isdir(os.path.join(here, ".git")):
        return
    try:
        r = subprocess.run(["git", "-c", f"safe.directory={here}", "-C", here, "pull", "--ff-only"],
                           capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        log(f"self-update skipped: {e}")
        return
    if r.returncode == 0 and "Already up to date" not in (r.stdout or ""):
        log("collector updated — installing any new tools, restarting")
        try:
            subprocess.run([sys.executable, str(COLLECT), "--check", "--yes"], timeout=600)
        except Exception:  # noqa: BLE001
            pass
        os.execv(sys.executable, [sys.executable, *sys.argv])


def monitor_ifaces():
    """Wireless interfaces on this box that support monitor mode — so the
    operator can pick one for a monitor-mode WiFi survey from the phone."""
    out = []
    try:
        dev = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=8).stdout
        for w in re.findall(r"Interface (\S+)", dev):
            info = subprocess.run(["iw", "dev", w, "info"], capture_output=True, text=True, timeout=5).stdout
            phy = re.search(r"wiphy (\d+)", info)
            if not phy:
                continue
            phyinfo = subprocess.run(["iw", "phy", f"phy{phy.group(1)}", "info"],
                                     capture_output=True, text=True, timeout=5).stdout
            # "Supported interface modes" block lists "* monitor" when capable
            if re.search(r"^\s*\*\s*monitor\s*$", phyinfo, re.MULTILINE):
                out.append(w)
    except Exception:  # noqa: BLE001 - best-effort; no iw or no wifi is fine
        pass
    return sorted(set(out))


def net_info():
    """Best-effort detection of the interface/CIDR/gateway we're plugged into,
    reusing the collector's detector, plus any monitor-capable WiFi adapters."""
    try:
        sys.path.insert(0, str(HERE))
        import collect  # noqa: PLC0415
        iface = collect.detect_interface(None)
        return {"interface": iface.get("name"), "cidr": iface.get("cidr"),
                "gateway": iface.get("gateway"), "wifi_ifaces": monitor_ifaces()}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "wifi_ifaces": monitor_ifaces()}


def enroll(conf, ident):
    try:
        _, r = _req(conf, ident, "POST", "/scanners/enroll",
                    body={"device_id": ident["device_id"], "token": ident["token"], "hostname": os.uname().nodename},
                    headers={"X-Enroll-Secret": conf.get("enroll_secret", "")})
        log(f"enrolled ({r.get('status')})")
    except urllib.error.HTTPError as e:
        log(f"enroll failed ({e.code}) — is the enrollment secret right?")
    except Exception as e:  # noqa: BLE001
        log(f"enroll error: {e}")


def heartbeat(conf, ident):
    try:
        _, r = _req(conf, ident, "POST", "/scanners/heartbeat", body={"net_info": net_info()})
        maybe_run_command(r)
        return r
    except Exception as e:  # noqa: BLE001
        log(f"heartbeat failed: {e}")
        return None


def maybe_run_command(r):
    """The hub delivers a queued power command once on heartbeat. Honour it —
    the operator drives the field unit from the phone, no console needed."""
    cmd = (r or {}).get("command")
    if cmd not in ("reboot", "poweroff"):
        return
    log(f"remote command received: {cmd} — executing")
    flag = "-r" if cmd == "reboot" else "-h"
    base = ["shutdown", flag, "now", f"TEQhub field-scanner {cmd}"]
    # service runs as root, so call shutdown directly; fall back to sudo -n if not
    argv = base if os.geteuid() == 0 else ["sudo", "-n", *base]
    try:
        subprocess.Popen(argv)  # fire-and-go; the box is on its way down
    except Exception as e:  # noqa: BLE001
        log(f"command failed ({e}); need root or passwordless sudo for shutdown")


def poll_job(conf, ident):
    try:
        _, r = _req(conf, ident, "GET", "/scanners/next-job")
        return r.get("job")
    except urllib.error.HTTPError as e:
        if e.code == 403:  # not claimed yet
            return None
        log(f"poll failed ({e.code})")
        return None
    except Exception as e:  # noqa: BLE001
        log(f"poll error: {e}")
        return None


def build_argv(params, outfile):
    argv = [sys.executable, str(COLLECT), "-o", outfile, "--no-submit", "--no-update", "--skip-check"]
    p = params
    if p.get("site"):          argv += ["--site", str(p["site"])]
    if p.get("location"):      argv += ["--location", str(p["location"])]
    if p.get("operator"):      argv += ["--operator", str(p["operator"])]
    if p.get("mode") == "passive": argv += ["--passive"]
    if p.get("iface"):         argv += ["--iface", str(p["iface"])]
    if p.get("wifi") is False: argv += ["--no-wifi"]
    if p.get("wifi_monitor"):  argv += ["--wifi-monitor", str(p["wifi_monitor"])]
    if p.get("speedtest"):     argv += ["--speedtest"]
    if p.get("snmp_community") and str(p["snmp_community"]) != "public":
        argv += ["--snmp-community", str(p["snmp_community"])]
    if str(p.get("listen", "")).strip().isdigit():        argv += ["--listen", str(p["listen"])]
    if str(p.get("nmap_timeout", "")).strip().isdigit():  argv += ["--nmap-timeout", str(p["nmap_timeout"])]
    return argv


def run_job(conf, ident, job):
    jid = job["id"]
    outfile = f"/tmp/scan-{jid}.json"
    argv = build_argv(job.get("params") or {}, outfile)
    log(f"running job {jid}: {' '.join(argv[2:])}")

    def progress(msg):
        try:
            _req(conf, ident, "POST", f"/scanners/jobs/{jid}/progress", body={"progress": msg}, timeout=20)
        except Exception:  # noqa: BLE001
            pass

    # A scan blocks this loop for minutes, and the collector's slow nmap phase can
    # go >90s with no output — long enough for the hub to mark us offline. Keep the
    # heartbeat going on a side thread for the life of the job so we stay online.
    stop_hb = threading.Event()

    def _hb_during_job():
        while not stop_hb.wait(HEARTBEAT_EVERY):
            heartbeat(conf, ident)

    hb_thread = threading.Thread(target=_hb_during_job, daemon=True)
    hb_thread.start()
    try:
        progress("starting scan")
        tail = []
        last_post = 0.0
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                tail.append(line)
                tail[:] = tail[-40:]
                # the collector logs each step as "[snapshot] <step>…" — surface it
                if "[snapshot]" in line and time.time() - last_post > 2:
                    progress(line.split("[snapshot]", 1)[1].strip()[:180])
                    last_post = time.time()
            rc = proc.wait()
        except Exception as e:  # noqa: BLE001
            _fail(conf, ident, jid, f"could not run collector: {e}")
            return

        if rc != 0 or not os.path.exists(outfile):
            _fail(conf, ident, jid, "collector failed:\n" + "\n".join(tail[-15:]))
            return

        progress("submitting results")
        try:
            snapshot = json.loads(Path(outfile).read_text())
            _, r = _req(conf, ident, "POST", f"/scanners/jobs/{jid}/result", body=snapshot, timeout=120)
            log(f"job {jid} done → snapshot {r.get('snapshot_id')}")
        except Exception as e:  # noqa: BLE001
            _fail(conf, ident, jid, f"submit failed: {e}")
        finally:
            try:
                os.remove(outfile)
            except OSError:
                pass
    finally:
        stop_hb.set()


def _fail(conf, ident, jid, err):
    log(f"job {jid} FAILED: {err.splitlines()[0] if err else err}")
    try:
        _req(conf, ident, "POST", f"/scanners/jobs/{jid}/failed", body={"error": err[:2000]}, timeout=20)
    except Exception:  # noqa: BLE001
        pass


def main():
    conf = load_conf()
    ident = identity()
    once = "--once" in sys.argv  # test mode: enroll + heartbeat + poll once, then exit
    if not once:
        self_update()  # pull latest collector + tools before we start (re-execs if changed)
    log(f"agent up as {ident['device_id']} → {conf['teqhub_url']}")
    enroll(conf, ident)

    if once:
        hb = heartbeat(conf, ident)
        log(f"heartbeat: {hb}")
        job = poll_job(conf, ident)
        log(f"poll: {'job ' + job['id'] if job else 'no job (or not claimed)'}")
        return

    last_hb = 0.0
    last_pull = time.time()
    while True:
        if time.time() - last_pull > UPDATE_EVERY:  # idle self-update; re-execs if changed
            self_update()
            last_pull = time.time()
        if time.time() - last_hb > HEARTBEAT_EVERY:
            heartbeat(conf, ident)
            last_hb = time.time()
        job = poll_job(conf, ident)
        if job:
            run_job(conf, ident, job)
            last_hb = 0.0  # heartbeat again promptly after a job
        else:
            time.sleep(IDLE_POLL)


if __name__ == "__main__":
    main()
