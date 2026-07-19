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
from datetime import datetime

from analyze import analyze, build_brief, CAT_LABEL, CAT_BLURB

# ── Palette / design tokens ──────────────────────────────────────────────────
# A restrained "security assessment" identity of its own — deliberately NOT
# coupled to TEQhub's design system, since this engine may move off later. Ink
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
            return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%b %-d, %Y · %-I:%M %p")
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
    if svg:
        P.append('<section><div class="pad">')
        P.append(head("Network Topology", "from SNMP/LLDP · this broadcast domain"))
        P.append(f'<div class="topo">{svg}')
        # neighbor detail table
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
        P.append('</div></div></section>')

    # ── 05 WiFi ──
    wifi = model["wifi"]
    if wifi:
        P.append('<section><div class="pad">')
        P.append(head("Wireless Survey", f"{len(wifi)} SSIDs in range"))
        P.append('<table class="tbl"><tr><th>SSID</th><th>Band / ch</th><th>Security</th><th class="num">Signal</th></tr>')
        for w in sorted(wifi, key=lambda x: -(x.get("signal") or 0)):
            sec = (w.get("security") or "").upper()
            if sec in ("OPEN", "", "NONE"):
                pill = '<span class="pill warn">OPEN</span>'
            elif sec in ("WEP", "WPA"):
                pill = f'<span class="pill mid">{esc(sec)}</span>'
            else:
                pill = f'<span class="pill ok">{esc(sec)}</span>'
            sig = w.get("signal")
            P.append(f'<tr><td><b>{esc(w.get("ssid") or "(hidden)")}</b></td>'
                     f'<td>{esc(w.get("band") or "")} · ch {esc(w.get("channel"))}</td>'
                     f'<td>{pill}</td><td class="num">{esc(sig)+"%" if sig is not None else "—"}</td></tr>')
        P.append('</table></div></section>')

    # ── 06 WAN — public IP (always, when reachable) + speed test (opt-in) ──
    # A 0 Mbps download means the speed test failed, not a real circuit — treat
    # it as "not measured" so the report never shows a misleading zero.
    has_speed = bool(wan.get("download_mbps"))
    if wan.get("public_ip") or has_speed:
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
             f'generated {esc(datetime.now().strftime("%Y-%m-%d %H:%M"))}.')
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
