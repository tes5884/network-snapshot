#!/usr/bin/env python3
"""
Network Snapshot — report renderer
==================================

Snapshot JSON → a self-contained, print-ready HTML report you can hand a
prospect or staple to a proposal. Stdlib only; the styling is inlined so the
file opens anywhere and prints straight to PDF (Ctrl-P → Save as PDF, or
`chromium --headless --print-to-pdf`).

    python3 report.py snapshot.json -o report.html
    python3 report.py snapshot.json -o report.html --narrative summary.md
    python3 report.py snapshot.json --brief brief.json      # emit AI input only

The report is fully useful with zero AI — the deterministic engine
(`analyze.py`) categorizes devices, ranks risks, and builds the scope
worksheet. `--narrative <file.md>` drops an AI-written executive summary into
the top slot; without it, a deterministic auto-summary is used. `--brief`
writes the compact, privacy-safe model that the AI narrator consumes.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from analyze import analyze, build_brief, CAT_LABEL, CAT_BLURB

# Reports are read on the US East Coast — show all times in Eastern (handles
# EST/EDT automatically). Falls back to UTC if the tz database is unavailable.
try:
    EASTERN = ZoneInfo("America/New_York")
except Exception:  # noqa: BLE001 — no tzdata → degrade to UTC rather than crash
    EASTERN = timezone.utc

# ── Palette / design tokens ──────────────────────────────────────────────────
# A restrained "security assessment" identity of its own — deliberately NOT
# coupled to any host app's design system, since this engine may move off later. Ink
# on paper-white with a single steel-blue accent and semantic severity colors.
CSS = """
:root{
  --paper:#ffffff; --ground:#f5f6f8; --ink:#12161c; --ink-2:#3a424e;
  --ink-3:#69727f; --line:#e2e6ec; --line-2:#eef1f5;
  --accent:#1f5f8b; --accent-soft:#e8f0f6;
  --hi:#c0392b; --hi-bg:#fbeceb; --med:#c77b1a; --med-bg:#fbf3e6;
  --low:#5a7a3e; --low-bg:#eef4e8; --info:#2f6f8f; --info-bg:#e8f1f5;
  --mono:"SFMono-Regular",ui-monospace,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.sheet{max-width:960px;margin:0 auto;background:var(--paper);
  box-shadow:0 1px 3px rgba(0,0,0,.08);}
.pad{padding:40px 48px}
h1,h2,h3{margin:0;line-height:1.2;text-wrap:balance}

/* Letterhead */
.letterhead{display:flex;align-items:center;justify-content:space-between;
  gap:16px;padding:16px 48px;background:#fff;border-bottom:1px solid var(--line)}
.letterhead img{height:32px;width:auto;display:block}
.letterhead .lh-tag{font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--ink-3);font-weight:600;white-space:nowrap}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
a{color:var(--accent);text-decoration:none}

/* Masthead */
.mast{background:var(--ink);color:#fff;padding:34px 48px 30px}
.mast .kicker{font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:#8fa3b5;font-weight:600}
.mast h1{font-size:27px;font-weight:700;margin:8px 0 4px}
.mast .site{font-size:18px;color:#cdd7e0;font-weight:500}
.mast .meta{display:flex;flex-wrap:wrap;gap:6px 26px;margin-top:18px;
  font-size:12.5px;color:#a9b6c4}
.mast .meta b{color:#e8eef3;font-weight:600}

/* KPI band */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);
  border-bottom:1px solid var(--line)}
.kpi{background:var(--paper);padding:18px 20px}
.kpi .n{font-size:26px;font-weight:700;letter-spacing:-.01em}
.kpi .l{font-size:11.5px;color:var(--ink-3);text-transform:uppercase;
  letter-spacing:.05em;margin-top:2px}
.kpi.sev-high .n{color:var(--hi)} .kpi.sev-med .n{color:var(--med)}

/* Section scaffolding */
section{border-top:1px solid var(--line);}
section:first-of-type{border-top:0}
.sec-head{display:flex;align-items:baseline;gap:12px;margin-bottom:18px}
.sec-head h2{font-size:16px;font-weight:700;letter-spacing:-.01em}
.sec-head .num{font-family:var(--mono);font-size:12px;color:var(--accent);
  font-weight:700}
.sec-head .hint{font-size:12px;color:var(--ink-3);margin-left:auto;font-weight:500}

/* Executive summary */
.exec{font-size:14.5px;line-height:1.62;color:var(--ink-2)}
.exec p{margin:0 0 11px}
.exec h3{font-size:14px;margin:18px 0 6px;color:var(--ink)}
.exec ul{margin:6px 0 12px;padding-left:20px}
.exec li{margin:3px 0}
.exec strong{color:var(--ink)}
.exec .autoflag{font-size:11px;color:var(--ink-3);font-style:italic}

/* Findings */
.finding{display:grid;grid-template-columns:76px 1fr;gap:16px;padding:15px 0;
  border-top:1px solid var(--line-2)}
.finding:first-child{border-top:0}
.chip{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:3px 8px;border-radius:4px;text-align:center;height:fit-content;
  white-space:nowrap}
.chip.high{background:var(--hi-bg);color:var(--hi)}
.chip.medium{background:var(--med-bg);color:var(--med)}
.chip.low{background:var(--low-bg);color:var(--low)}
.chip.info{background:var(--info-bg);color:var(--info)}
.finding .ft{font-weight:650;font-size:14px}
.finding .fd{color:var(--ink-2);font-size:13px;margin-top:2px}
.finding .fh{margin-top:7px;font-family:var(--mono);font-size:11.5px;
  color:var(--ink-3);background:var(--ground);border:1px solid var(--line);
  border-radius:5px;padding:6px 9px}
.finding .fh div{padding:1px 0}
.finding .scope{margin-top:6px;font-size:12px;color:var(--accent)}
.finding .scope b{color:var(--ink-2);font-weight:600}

/* Device inventory */
.catgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.catcard{border:1px solid var(--line);border-radius:8px;overflow:hidden;
  break-inside:avoid}
.catcard .ch{display:flex;align-items:center;gap:9px;padding:10px 14px;
  background:var(--ground);border-bottom:1px solid var(--line)}
.catcard .ch .cn{font-weight:700;font-size:13.5px}
.catcard .ch .cc{margin-left:auto;font-family:var(--mono);font-weight:700;
  font-size:13px;background:var(--ink);color:#fff;border-radius:11px;
  min-width:22px;height:22px;display:flex;align-items:center;justify-content:center;
  padding:0 7px}
.catcard .cb{font-size:11px;color:var(--ink-3);padding:0 14px 8px;background:var(--ground);
  border-bottom:1px solid var(--line)}
.dev{display:grid;grid-template-columns:88px 1fr auto;gap:10px;align-items:baseline;
  padding:7px 14px;border-top:1px solid var(--line-2);font-size:12.5px}
.dev:first-child{border-top:0}
.dev .ip{font-family:var(--mono);color:var(--ink-3);font-size:11.5px}
.dev .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dev .nm .vn{font-weight:400;color:var(--ink-3);font-size:11px}
.dev .pt{font-family:var(--mono);font-size:10.5px;color:var(--ink-3);text-align:right}
.dev.lc .nm::after{content:"?";color:var(--med);font-weight:700;margin-left:5px;
  font-size:11px}
.dupe{font-size:10px;color:var(--ink-3);font-style:italic}

/* Topology */
.uplink{background:var(--accent-soft);border:1px solid var(--line);border-radius:8px;
  padding:9px 13px;margin-bottom:10px;font-size:13px;color:var(--ink-2)}
.topo{background:var(--ground);border:1px solid var(--line);border-radius:8px;
  padding:20px;overflow-x:auto}
.topo svg{display:block;margin:0 auto;max-width:100%}
.nbr-tbl{width:100%;border-collapse:collapse;margin-top:14px;font-size:12px}
.nbr-tbl th{text-align:left;color:var(--ink-3);font-weight:600;font-size:11px;
  text-transform:uppercase;letter-spacing:.04em;padding:5px 10px;border-bottom:1px solid var(--line)}
.nbr-tbl td{padding:5px 10px;border-bottom:1px solid var(--line-2)}
.nbr-tbl .mono{font-size:11.5px}

/* Generic table (wifi, scope) */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;color:var(--ink-3);font-weight:600;font-size:11px;
  text-transform:uppercase;letter-spacing:.04em;padding:8px 12px;
  border-bottom:2px solid var(--line)}
.tbl td{padding:8px 12px;border-bottom:1px solid var(--line-2)}
.tbl tr:last-child td{border-bottom:0}
.tbl .num{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}
.pill{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:4px}
.pill.ok{background:var(--low-bg);color:var(--low)}
.pill.warn{background:var(--hi-bg);color:var(--hi)}
.pill.mid{background:var(--med-bg);color:var(--med)}

.wan-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;text-align:center}
.wan-cards .wc{border:1px solid var(--line);border-radius:8px;padding:18px 16px;background:var(--ground)}
.wan-cards .wc.dn{border-color:#bcd3c4;background:var(--low-bg)}
.wan-cards .wc .n{font-size:30px;font-weight:700;letter-spacing:-.02em}
.wan-cards .wc .n .arw{font-size:15px;margin-right:4px;vertical-align:2px}
.wan-cards .wc.dn .n .arw{color:var(--low)} .wan-cards .wc.up .n .arw{color:var(--accent)}
.wan-cards .wc.pg .n .arw{color:var(--ink-3)}
.wan-cards .wc .u{font-size:11px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.wan-cap{margin-top:11px;font-size:12px;color:var(--ink-3);text-align:center}
.wan-cap code{font-family:var(--mono);font-size:11px;background:var(--ground);padding:1px 4px;border-radius:3px}
.wan-ip{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;border:1px solid var(--accent);
  background:var(--accent-soft);border-radius:8px;padding:14px 18px;margin-bottom:14px}
.wan-ip .l{font-size:11px;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;font-weight:700}
.wan-ip .v{font-size:22px;font-weight:700;letter-spacing:-.01em;color:var(--ink)}
.wan-ip .o{font-size:12px;color:var(--ink-3);margin-left:auto}

.foot{padding:22px 48px 34px;color:var(--ink-3);font-size:11.5px;line-height:1.6;
  border-top:1px solid var(--line)}
.foot b{color:var(--ink-2)}
.empty{color:var(--ink-3);font-size:13px;font-style:italic}

@media print{
  body{background:#fff;font-size:12px}
  .sheet{box-shadow:none;max-width:none}
  section{break-inside:avoid}
  .catcard,.finding{break-inside:avoid}
  .pad{padding:22px 30px}
}
@media (max-width:680px){
  .kpis{grid-template-columns:repeat(2,1fr)}
  .catgrid{grid-template-columns:1fr}
  .wan-cards{grid-template-columns:1fr}
  .pad{padding:26px 22px}
}
"""

# TEQbytes letterhead logo, embedded so the report stays self-contained.
LOGO_DATA_URI = "data:image/png;base64,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"


E = html.escape


def esc(s):
    return E(str(s)) if s is not None else ""


# ── tiny markdown → HTML (for the AI narrative) ──────────────────────────────
def md_to_html(md):
    out, in_ul = [], False
    for raw in md.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if in_ul:
                out.append("</ul>"); in_ul = False
            continue
        m = re.match(r"(#{1,3})\s+(.*)", line)
        if m:
            if in_ul: out.append("</ul>"); in_ul = False
            lvl = len(m.group(1)); out.append(f"<h3>{_inline(m.group(2))}</h3>" if lvl >= 2 else f"<h3>{_inline(m.group(2))}</h3>")
            continue
        if re.match(r"[-*]\s+", line):
            if not in_ul: out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline(re.sub(r'^[-*]\\s+','',line))}</li>")
            continue
        if in_ul: out.append("</ul>"); in_ul = False
        out.append(f"<p>{_inline(line)}</p>")
    if in_ul: out.append("</ul>")
    return "\n".join(out)


def _inline(s):
    s = E(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


# ── auto executive summary (used when no AI narrative supplied) ──────────────
def auto_summary(model):
    net = model["network"]
    cc = model["category_counts"]
    n = model["host_count"]
    highs = [f for f in model["findings"] if f["severity"] == "high"]
    gw = net.get("gateway") or {}
    parts = []

    lead = f"This snapshot found <strong>{n} active devices</strong> on the network"
    if net.get("subnets_seen"):
        lead += f" ({esc(', '.join(net['subnets_seen']))})"
    if gw.get("identity"):
        lead += f", behind a <strong>{esc(gw['identity'])}</strong> {esc(gw.get('role_guess','gateway'))}"
    lead += "."
    parts.append(f"<p>{lead}</p>")

    # composition sentence
    bits = []
    for k in ("server", "workstation", "camera", "printer", "switch", "ap", "voip", "iot"):
        if cc.get(k):
            bits.append(f"{cc[k]} {CAT_LABEL[k].split(' / ')[0].lower()}"
                        + ("s" if cc[k] != 1 and not CAT_LABEL[k].endswith("s") else ""))
    if bits:
        parts.append(f"<p>The mix includes {esc(', '.join(bits[:-1]))}"
                     + (f", and {esc(bits[-1])}" if len(bits) > 1 else esc(bits[0]) if bits else "")
                     + ".</p>")

    if highs:
        parts.append("<h3>What stands out</h3><ul>"
                     + "".join(f"<li><strong>{esc(f['title'])}</strong> — {esc(f['detail'])}</li>" for f in highs[:4])
                     + "</ul>")
    if not net.get("vlans_seen"):
        parts.append("<p>The network appears <strong>flat</strong> — no VLAN segmentation was observed, "
                     "so every device shares one broadcast domain. That is the single biggest structural "
                     "finding and the clearest onboarding opportunity.</p>")
    parts.append('<p class="autoflag">Auto-generated summary — replace with an AI narrative via '
                 "<code>--narrative</code> for prospect-facing polish.</p>")
    return "\n".join(parts)


# ── topology SVG (internet → firewall → switches spine) ──────────────────────
def topo_svg(net):
    gw = net.get("gateway") or {}
    switches = net.get("snmp_devices", [])
    if not gw and not switches:
        return None
    box_w, box_h, gap = 150, 46, 34
    n_sw = max(len(switches), 0)
    cols = max(n_sw, 1)
    width = max(cols * box_w + (cols - 1) * gap + 40, 380)
    height = 260
    cx = width / 2

    def box(x, y, top, bot, fill, stroke, tcol="#12161c"):
        return (f'<g><rect x="{x-box_w/2:.0f}" y="{y:.0f}" width="{box_w}" height="{box_h}" rx="7" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
                f'<text x="{x:.0f}" y="{y+19:.0f}" text-anchor="middle" font-size="12.5" '
                f'font-weight="700" fill="{tcol}">{esc(top)[:20]}</text>'
                f'<text x="{x:.0f}" y="{y+34:.0f}" text-anchor="middle" font-size="10" '
                f'fill="#69727f">{esc(bot)[:24]}</text></g>')

    def line(x1, y1, x2, y2):
        return f'<path d="M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}" stroke="#9aa6b2" stroke-width="1.5" fill="none"/>'

    s = [f'<svg viewBox="0 0 {width:.0f} {height}" width="{width:.0f}" height="{height}" '
         'xmlns="http://www.w3.org/2000/svg">']
    y_inet, y_fw, y_sw = 8, 92, 186
    # internet
    s.append(box(cx, y_inet, "Internet", "WAN uplink", "#eef1f5", "#cbd3dc", "#3a424e"))
    s.append(line(cx, y_inet + box_h, cx, y_fw))
    # firewall
    fw_id = gw.get("identity") or gw.get("vendor") or "Gateway"
    s.append(box(cx, y_fw, fw_id, gw.get("ipv4") or gw.get("role_guess") or "firewall", "#e8f0f6", "#1f5f8b"))
    # switches row
    if switches:
        xs = [(width - (cols * box_w + (cols - 1) * gap)) / 2 + i * (box_w + gap) + box_w / 2
              for i in range(cols)]
        for i, sw in enumerate(switches):
            x = xs[i]
            s.append(line(cx, y_fw + box_h, x, y_sw))
            label = sw.get("sysname") or sw.get("ip") or "switch"
            sub = (sw.get("sysdescr") or "")[:24] or f"{sw.get('neighbor_count',0)} neighbors"
            s.append(box(x, y_sw, label, sub, "#fff", "#cbd3dc"))
    else:
        s.append(f'<text x="{cx:.0f}" y="{y_sw+20:.0f}" text-anchor="middle" font-size="11" '
                 'fill="#69727f">No managed switches answered SNMP</text>')
    s.append("</svg>")
    return "".join(s)


def _port_summary(rec, limit=4):
    seen, out = set(), []
    for p in rec.get("open_ports", []):
        svc = p.get("service") or p.get("port")
        if svc in seen: continue
        seen.add(svc)
        out.append(str(p.get("port")))
        if len(out) >= limit: break
    extra = len(rec.get("ports", [])) - len(out)
    return ("·".join(out) + (f" +{extra}" if extra > 0 else "")) if out else ""


# ── render ───────────────────────────────────────────────────────────────────
def render(model, narrative_md=None):
    scan = model["scan"]
    net = model["network"]
    cc = model["category_counts"]
    findings = model["findings"]
    n_high = sum(1 for f in findings if f["severity"] == "high")
    n_med = sum(1 for f in findings if f["severity"] == "medium")

    def fmt_dt(s):
        if not s: return "—"
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:  # naive → assume the collector's UTC
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(EASTERN).strftime("%b %-d, %Y · %-I:%M %p %Z")
        except Exception:
            return esc(s)

    P = []  # page parts
    # ── masthead ──
    iface = scan.get("interface") or {}
    meta_bits = [
        ("Scanned", fmt_dt(scan.get("finished_at") or scan.get("started_at"))),
        ("Mode", esc((scan.get("mode") or "active").title())),
        ("Drop point", esc(scan.get("location") or iface.get("name") or "—")),
        ("Operator", esc(scan.get("operator") or "—")),
    ]
    if LOGO_DATA_URI:
        P.append(f'<div class="letterhead"><img src="{LOGO_DATA_URI}" alt="TEQbytes">'
                 '<span class="lh-tag">Network Assessment</span></div>')
    P.append('<div class="mast">')
    P.append('<div class="kicker">Network Discovery Snapshot</div>')
    P.append(f'<h1>{esc(scan.get("site_label") or "Untitled Site")}</h1>')
    if scan.get("coverage_note"):
        P.append(f'<div class="site">{esc(scan["coverage_note"])}</div>')
    P.append('<div class="meta">' + "".join(f'<span>{l} <b>{v}</b></span>' for l, v in meta_bits) + '</div>')
    P.append('</div>')

    # ── KPI band ──
    wan = net.get("wan") or {}
    kpis = [
        ("", str(model["host_count"]), "Devices found"),
        ("sev-high" if n_high else "", str(n_high), "High-risk flags"),
        ("sev-med" if n_med else "", str(n_med), "Medium flags"),
        ("", (f'{wan.get("download_mbps"):.0f}' if wan.get("download_mbps") else str(len(cc))),
         "Mbps down" if wan.get("download_mbps") else "Device types"),
    ]
    P.append('<div class="kpis">' + "".join(
        f'<div class="kpi {c}"><div class="n mono">{esc(v)}</div><div class="l">{esc(l)}</div></div>'
        for c, v, l in kpis) + '</div>')

    secn = [0]
    def head(title, hint=""):
        secn[0] += 1
        return (f'<div class="sec-head"><span class="num">{secn[0]:02d}</span>'
                f'<h2>{esc(title)}</h2>' + (f'<span class="hint">{esc(hint)}</span>' if hint else "") + '</div>')

    # ── 01 Executive summary ──
    P.append('<section><div class="pad">')
    P.append(head("Executive Summary"))
    P.append(f'<div class="exec">{md_to_html(narrative_md) if narrative_md else auto_summary(model)}</div>')
    P.append('</div></section>')

    # ── 02 Findings ──
    P.append('<section><div class="pad">')
    P.append(head("Risks & Opportunities", f"{len(findings)} flags, most severe first"))
    if findings:
        for f in findings:
            P.append('<div class="finding">')
            P.append(f'<div class="chip {f["severity"]}">{esc(f["severity"] if f["kind"]=="risk" else "note")}</div>')
            P.append('<div>')
            P.append(f'<div class="ft">{esc(f["title"])}</div>')
            P.append(f'<div class="fd">{esc(f["detail"])}</div>')
            if f["hosts"]:
                shown = f["hosts"][:6]
                more = len(f["hosts"]) - len(shown)
                P.append('<div class="fh">' + "".join(f'<div>{esc(h)}</div>' for h in shown)
                         + (f'<div>+{more} more…</div>' if more > 0 else "") + '</div>')
            if f.get("scope_hint"):
                P.append(f'<div class="scope"><b>Onboarding:</b> {esc(f["scope_hint"])}</div>')
            P.append('</div></div>')
    else:
        P.append('<div class="empty">No notable risks flagged by the deterministic checks.</div>')
    P.append('</div></section>')

    # ── 03 Device inventory ──
    P.append('<section><div class="pad">')
    P.append(head("Device Inventory", f"{model['host_count']} devices, grouped"))
    P.append('<div class="catgrid">')
    for cat, recs in model["categories"].items():
        P.append('<div class="catcard">')
        P.append(f'<div class="ch"><span class="cn">{esc(CAT_LABEL[cat])}</span>'
                 f'<span class="cc">{len(recs)}</span></div>')
        P.append(f'<div class="cb">{esc(CAT_BLURB[cat])}</div>')
        for r in recs:
            nm = r.get("name") or ""
            vn = r.get("vendor") or ""
            label = esc(nm) if nm else f'<span class="vn">{esc(vn) or "unidentified"}</span>'
            if nm and vn:
                label = f'{esc(nm)} <span class="vn">· {esc(vn)}</span>'
            dupe = f'<div class="dupe">also {esc(", ".join(r["also_ips"]))}</div>' if r.get("also_ips") else ""
            lc = " lc" if r.get("confidence") == "low" else ""
            P.append(f'<div class="dev{lc}"><span class="ip">{esc(r.get("ipv4"))}</span>'
                     f'<span class="nm">{label}{dupe}</span>'
                     f'<span class="pt">{esc(_port_summary(r))}</span></div>')
        P.append('</div>')
    P.append('</div></section>')

    # ── 04 Topology ──
    svg = topo_svg(net)
    uplink = next((n for n in (net.get("lldp_neighbors") or []) if n.get("switch_name") or n.get("switch_port")), None)
    stp = net.get("stp") or {}
    if svg or uplink or stp.get("present"):
        P.append('<section><div class="pad">')
        P.append(head("Network Topology", "from LLDP/SNMP · this broadcast domain"))

        # Uplink — which switch/port this jack is plugged into (from LLDP/CDP).
        if uplink:
            bits = []
            if uplink.get("switch_port"): bits.append(f"port <b>{esc(uplink['switch_port'])}</b>")
            if uplink.get("vlan"): bits.append(f"VLAN {esc(uplink['vlan'])}")
            if uplink.get("mgmt_ip"): bits.append(f"mgmt {esc(uplink['mgmt_ip'])}")
            if uplink.get("poe"): bits.append("PoE")
            P.append(f'<div class="uplink">🔌 This jack connects to <b>{esc(uplink.get("switch_name") or "a switch")}</b>'
                     + (" · " + " · ".join(bits) if bits else "") + '</div>')

        # Spanning tree — from the BPDUs on this segment.
        if stp.get("present"):
            root = stp.get("root") or {}
            vlabel = {"rstp": "RSTP (802.1w)", "mstp": "MSTP (802.1s)", "stp": "STP (802.1D, legacy)"}.get(stp.get("version"), "STP")
            where = "this switch is the root" if stp.get("is_root_here") else f"root is {esc(root.get('mac') or '?')}"
            P.append(f'<div class="uplink">🌳 Spanning tree: <b>{esc(vlabel)}</b> · {where}'
                     + (f" (priority {esc(root.get('priority'))})" if root.get("priority") is not None else "") + '</div>')
        elif (uplink or svg) and "present" in stp:
            P.append('<div class="uplink" style="color:var(--ink-3)">🌳 No spanning-tree BPDUs seen on this segment.</div>')

        if svg:
            P.append(f'<div class="topo">{svg}')
            edges = net.get("snmp_devices", [])
            nbrs = [(d.get("sysname") or d.get("ip"), nb.get("local_port"), nb.get("neighbor_name"), nb.get("neighbor_port"))
                    for d in edges for nb in d.get("neighbors", [])]
            if nbrs:
                P.append('<table class="nbr-tbl"><tr><th>Switch</th><th>Local port</th>'
                         '<th>Connected to</th><th>Remote port</th></tr>')
                for sw, lp, nn, npp in nbrs:
                    P.append(f'<tr><td>{esc(sw)}</td><td class="mono">{esc(lp)}</td>'
                             f'<td>{esc(nn)}</td><td class="mono">{esc(npp)}</td></tr>')
                P.append('</table>')
            P.append('</div>')
        P.append('</div></section>')

    # ── 05 WiFi ──
    wifi = model["wifi"]
    if wifi:
        P.append('<section><div class="pad">')
        P.append(head("Wireless Survey", f"{len(wifi)} SSIDs in range"))
        P.append('<table class="tbl"><tr><th>SSID</th><th>AP (BSSID)</th><th>Band / ch</th><th>Security</th><th class="num">Signal</th></tr>')
        for w in sorted(wifi, key=lambda x: -(x.get("signal") or 0)):
            sec = (w.get("security") or "").upper()
            if sec in ("OPEN", "", "NONE"):
                pill = '<span class="pill warn">OPEN</span>'
            elif sec in ("WEP", "WPA"):
                pill = f'<span class="pill mid">{esc(sec)}</span>'
            else:
                pill = f'<span class="pill ok">{esc(sec)}</span>'
            sig = w.get("signal")
            bssid = w.get("bssid")
            P.append(f'<tr><td><b>{esc(w.get("ssid") or "(hidden)")}</b></td>'
                     f'<td><code>{esc(bssid) if bssid else "—"}</code></td>'
                     f'<td>{esc(w.get("band") or "")} · ch {esc(w.get("channel"))}</td>'
                     f'<td>{pill}</td><td class="num">{esc(sig)+"%" if sig is not None else "—"}</td></tr>')
        P.append('</table></div></section>')

    # ── 06 WAN — public IP (always, when reachable) + speed test (opt-in) ──
    # A 0 Mbps download means the speed test failed, not a real circuit — treat
    # it as "not measured" so the report never shows a misleading zero.
    has_speed = bool(wan.get("download_mbps"))
    circ = net.get("circuit") or {}
    has_circuit = circ.get("loss_pct") is not None or bool(circ.get("first_hops"))
    if wan.get("public_ip") or has_speed or has_circuit:
        server = wan.get("server")
        hint = " · ".join(x for x in [wan.get("isp"), wan.get("geo")] if x)
        P.append('<section><div class="pad">')
        P.append(head("Internet Circuit", esc(hint)))
        # Public IP band — the WAN address, prominent.
        if wan.get("public_ip"):
            P.append('<div class="wan-ip"><div class="l">Public / WAN IP</div>'
                     f'<div class="v mono">{esc(wan["public_ip"])}</div>'
                     + (f'<div class="o">{esc(wan.get("isp"))}</div>' if wan.get("isp") else "")
                     + '</div>')
        # Circuit health — loss / latency / jitter + double-NAT.
        if has_circuit:
            parts = []
            if circ.get("loss_pct") is not None: parts.append(f"{circ['loss_pct']:.0f}% loss")
            if circ.get("latency_ms") is not None: parts.append(f"{circ['latency_ms']:.0f}ms latency")
            if circ.get("jitter_ms") is not None: parts.append(f"{circ['jitter_ms']:.0f}ms jitter")
            if circ.get("double_nat"): parts.append("⚠ double-NAT")
            if parts:
                P.append(f'<div class="uplink">📶 Circuit health: {esc(" · ".join(parts))}</div>')
        if has_speed:
            P.append('<div class="wan-cards">')
            cards = [
                ("dn", "▼", f'{wan.get("download_mbps"):.0f}', "Mbps download"),
                ("up", "▲", f'{wan.get("upload_mbps"):.0f}' if wan.get("upload_mbps") is not None else "—", "Mbps upload"),
                ("pg", "•", f'{wan.get("ping_ms"):.0f}' if wan.get("ping_ms") is not None else "—", "ms latency"),
            ]
            for cls, arw, n, u in cards:
                P.append(f'<div class="wc {cls}"><div class="n mono"><span class="arw">{arw}</span>{esc(n)}</div>'
                         f'<div class="u">{esc(u)}</div></div>')
            P.append('</div>')
            if server:
                P.append(f'<div class="wan-cap">Speed measured live during the scan against {esc(server)}'
                         + (f' via {esc(wan.get("isp"))}' if wan.get("isp") else "") + '.</div>')
        else:
            P.append('<div class="wan-cap">Speed test not run — pass <code>--speedtest</code> to measure '
                     'download/upload/latency (it briefly saturates the circuit).</div>')
        P.append('</div></section>')

    # ── 07 Onboarding scope ──
    if model["scope"]:
        P.append('<section><div class="pad">')
        P.append(head("Onboarding Scope Worksheet", "deterministic counts → managed-service lines"))
        P.append('<table class="tbl"><tr><th>Category</th><th class="num">Count</th><th>Managed-service implication</th></tr>')
        for r in model["scope"]:
            P.append(f'<tr><td><b>{esc(r["category"])}</b></td>'
                     f'<td class="num">{esc(r["count"])}</td>'
                     f'<td>{esc(r["note"])}</td></tr>')
        P.append('</table></div></section>')

    # ── footer ──
    tp = scan.get("tools_present") or {}
    missing = [t for t, ok in tp.items() if not ok]
    P.append('<div class="foot">')
    P.append(f'<b>Methodology.</b> {esc(scan.get("coverage_note") or "Single broadcast domain from one drop point.")} '
             'Devices are categorized deterministically from MAC-OUI vendor, open ports, mDNS advertisements, and SNMP role; '
             'a <b>?</b> marks a low-confidence guess. This is a point-in-time picture of one network segment, not an exhaustive audit — '
             'a device that was powered off or on another VLAN will not appear.')
    if missing:
        P.append(f' Tools unavailable during this scan: {esc(", ".join(missing))}.')
    P.append(f'<br>Collector {esc(scan.get("collector_version") or "?")} · analyzer {esc(model["analyzer_version"])} · '
             f'generated {esc(datetime.now(EASTERN).strftime("%Y-%m-%d %H:%M %Z"))}.')
    P.append('</div>')

    body = f'<div class="sheet">{"".join(P)}</div>'
    title = esc(scan.get("site_label") or "Network Snapshot")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{title} — Network Snapshot</title><style>{CSS}</style></head>'
            f'<body>{body}</body></html>')


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a network snapshot into an HTML report.")
    ap.add_argument("snapshot", help="snapshot JSON from collect.py")
    ap.add_argument("-o", "--output", help="HTML output path (default: <site>-report.html)")
    ap.add_argument("--narrative", help="markdown file with an AI-written executive summary")
    ap.add_argument("--brief", help="write the AI-input brief JSON to this path and exit")
    args = ap.parse_args(argv)

    with open(args.snapshot) as fh:
        snapshot = json.load(fh)
    model = analyze(snapshot)

    if args.brief:
        with open(args.brief, "w") as fh:
            json.dump(build_brief(model), fh, indent=2, default=str)
        print(f"Brief written: {args.brief}")
        return 0

    narrative = None
    if args.narrative:
        with open(args.narrative) as fh:
            narrative = fh.read()

    out = args.output
    if not out:
        slug = re.sub(r"[^a-z0-9]+", "-", (model["scan"].get("site_label") or "network").lower()).strip("-")
        out = f"{slug}-report.html"
    html_doc = render(model, narrative)
    with open(out, "w") as fh:
        fh.write(html_doc)
    print(f"Report written: {out}  ({model['host_count']} devices, "
          f"{len(model['findings'])} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
