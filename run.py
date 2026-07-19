#!/usr/bin/env python3
"""
Network Snapshot — launcher TUI
===============================

A tiny terminal UI so you don't have to remember collect.py's flags. Fill in
the fields, hit Run, and it invokes the collector. Stdlib only (curses), same
"runs anywhere" posture as the collector.

    sudo python3 run.py

Needs sudo because the scan does (arp-scan/nmap raw sockets). If curses can't
start (no TTY, dumb terminal), it falls back to a plain question-and-answer
wizard automatically.
"""

from __future__ import annotations

import curses
import os
import shlex
import subprocess
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(HERE, "collect.py")


def default_output() -> str:
    return f"snapshot-{datetime.now().strftime('%Y%m%d-%H%M')}.json"


# Field model — data-driven so the render/edit loop stays generic.
# kind: "text" | "bool" | "choice" | "action"
def make_fields() -> list[dict]:
    return [
        {"key": "site", "label": "Site / prospect", "kind": "text", "value": "", "hint": "the merge key — same label = same site"},
        {"key": "location", "label": "Drop location", "kind": "text", "value": "", "hint": "e.g. 'server room / camera VLAN' — context only"},
        {"key": "operator", "label": "Operator", "kind": "text", "value": os.environ.get("SUDO_USER") or os.environ.get("USER") or "", "hint": "who is running this"},
        {"key": "mode", "label": "Scan mode", "kind": "choice", "value": "active", "choices": ["active", "passive"], "hint": "active probes (arp-scan+nmap); passive only listens"},
        {"key": "iface", "label": "Interface", "kind": "text", "value": "", "hint": "blank = auto-detect the default route's NIC"},
        {"key": "wifi", "label": "WiFi survey", "kind": "bool", "value": True, "hint": "scan nearby SSIDs / encryption"},
        {"key": "wifi_monitor", "label": "Monitor iface", "kind": "text", "value": "", "hint": "monitor-mode adapter (e.g. wlan1, Alfa card); blank = basic scan"},
        {"key": "speedtest", "label": "WAN speed test", "kind": "bool", "value": False, "hint": "measures the internet circuit — saturates it for ~30s"},
        {"key": "snmp_community", "label": "SNMP community", "kind": "text", "value": "public", "hint": "comma-separated read communities to try"},
        {"key": "listen", "label": "Listen seconds", "kind": "text", "value": "20", "hint": "time for passive listeners (LLDP/mDNS/sniff)"},
        {"key": "nmap_timeout", "label": "nmap cap (s)", "kind": "text", "value": "1800", "hint": "hard limit on the active nmap phase"},
        {"key": "output", "label": "Output file", "kind": "text", "value": default_output(), "hint": "where the snapshot JSON is written"},
        {"key": "_run", "label": "▶  Run scan", "kind": "action", "value": None, "hint": "start the collector with these settings"},
        {"key": "_quit", "label": "✕  Quit", "kind": "action", "value": None, "hint": "exit without scanning"},
    ]


def build_argv(fields: list[dict]) -> list[str]:
    f = {x["key"]: x["value"] for x in fields}
    argv = [sys.executable, COLLECTOR, "-o", f["output"]]
    if f["site"].strip():
        argv += ["--site", f["site"].strip()]
    if f["location"].strip():
        argv += ["--location", f["location"].strip()]
    if f["operator"].strip():
        argv += ["--operator", f["operator"].strip()]
    if f["mode"] == "passive":
        argv += ["--passive"]
    if f["iface"].strip():
        argv += ["--iface", f["iface"].strip()]
    if not f["wifi"]:
        argv += ["--no-wifi"]
    if f["wifi_monitor"].strip():
        argv += ["--wifi-monitor", f["wifi_monitor"].strip()]
    if f["speedtest"]:
        argv += ["--speedtest"]
    if f["snmp_community"].strip() and f["snmp_community"].strip() != "public":
        argv += ["--snmp-community", f["snmp_community"].strip()]
    if str(f["listen"]).strip().isdigit():
        argv += ["--listen", str(f["listen"]).strip()]
    if str(f["nmap_timeout"]).strip().isdigit():
        argv += ["--nmap-timeout", str(f["nmap_timeout"]).strip()]
    return argv


def run_collector(fields: list[dict]) -> None:
    argv = build_argv(fields)
    print("\n\033[1mRunning:\033[0m " + shlex.join(argv) + "\n")
    if os.geteuid() != 0:
        print("\033[33m! Not root — active scans (arp-scan/nmap) need sudo. "
              "Re-run with: sudo python3 run.py\033[0m\n")
    try:
        subprocess.run(argv)
    except KeyboardInterrupt:
        print("\n\033[33mScan interrupted.\033[0m")
    print("\nDone. Snapshot: " + next((x["value"] for x in fields if x["key"] == "output"), "?"))


# ── curses TUI ───────────────────────────────────────────────────────────────

def tui(stdscr, fields: list[dict]) -> str:
    curses.curs_set(0)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # title
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # hint
        curses.init_pair(4, curses.COLOR_GREEN, -1)    # action

    sel = 0
    editing = False
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(0, 2, "Network Snapshot", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(1, 2, "↑/↓ move · Enter edit/select · Space toggle · q quit", curses.color_pair(3))

        row = 3
        label_w = max(len(f["label"]) for f in fields) + 2
        for i, f in enumerate(fields):
            is_sel = i == sel
            attr = curses.color_pair(2) if is_sel else curses.A_NORMAL
            if f["kind"] == "action":
                text = f["label"]
                col = curses.color_pair(4) | curses.A_BOLD if not is_sel else attr
                stdscr.addstr(row, 4, text.ljust(label_w + 22)[: w - 6], col)
            else:
                stdscr.addstr(row, 4, f["label"].rjust(label_w), curses.A_BOLD if is_sel else curses.A_DIM)
                if f["kind"] == "bool":
                    val = "[x] yes" if f["value"] else "[ ] no"
                elif f["kind"] == "choice":
                    val = " ".join(f"<{c}>" if c == f["value"] else c for c in f["choices"])
                else:
                    val = str(f["value"])
                    if editing and is_sel:
                        val += "▏"
                vattr = attr if is_sel else curses.A_NORMAL
                stdscr.addstr(row, 4 + label_w + 2, val[: w - (6 + label_w)], vattr)
            row += 1

        # hint for current field
        stdscr.addstr(min(row + 1, h - 2), 4, "› " + fields[sel]["hint"], curses.color_pair(3))
        stdscr.refresh()

        c = stdscr.getch()
        f = fields[sel]

        if editing and f["kind"] == "text":
            if c in (curses.KEY_ENTER, 10, 13):
                editing = False
            elif c in (27,):  # ESC
                editing = False
            elif c in (curses.KEY_BACKSPACE, 127, 8):
                f["value"] = f["value"][:-1]
            elif 32 <= c <= 126:
                f["value"] += chr(c)
            continue

        if c in (ord("q"), 27):
            return "quit"
        elif c in (curses.KEY_UP, ord("k")):
            sel = (sel - 1) % len(fields)
        elif c in (curses.KEY_DOWN, ord("j"), 9):
            sel = (sel + 1) % len(fields)
        elif c == ord(" ") and f["kind"] == "bool":
            f["value"] = not f["value"]
        elif c in (curses.KEY_LEFT, curses.KEY_RIGHT) and f["kind"] == "choice":
            i = f["choices"].index(f["value"])
            f["value"] = f["choices"][(i + (1 if c == curses.KEY_RIGHT else -1)) % len(f["choices"])]
        elif c in (curses.KEY_ENTER, 10, 13):
            if f["kind"] == "action":
                return "run" if f["key"] == "_run" else "quit"
            elif f["kind"] == "text":
                editing = True
            elif f["kind"] == "bool":
                f["value"] = not f["value"]
            elif f["kind"] == "choice":
                i = f["choices"].index(f["value"])
                f["value"] = f["choices"][(i + 1) % len(f["choices"])]


# ── plain wizard fallback (no curses / no TTY) ───────────────────────────────

def wizard(fields: list[dict]) -> str:
    print("Network Snapshot — press Enter to accept the [default].\n")
    for f in fields:
        if f["kind"] == "action":
            continue
        if f["kind"] == "bool":
            ans = input(f"{f['label']} (y/n) [{'y' if f['value'] else 'n'}]: ").strip().lower()
            if ans:
                f["value"] = ans.startswith("y")
        elif f["kind"] == "choice":
            ans = input(f"{f['label']} {f['choices']} [{f['value']}]: ").strip().lower()
            if ans in f["choices"]:
                f["value"] = ans
        else:
            ans = input(f"{f['label']} [{f['value']}]: ").strip()
            if ans:
                f["value"] = ans
    print("\n  " + shlex.join(build_argv(fields)))
    return "run" if input("\nRun this scan? [Y/n]: ").strip().lower() in ("", "y", "yes") else "quit"


def main() -> int:
    fields = make_fields()
    try:
        action = curses.wrapper(tui, fields)
    except Exception:  # noqa: BLE001 — no TTY / dumb terminal → wizard
        action = wizard(fields)
    if action == "run":
        run_collector(fields)
    else:
        print("No scan run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
