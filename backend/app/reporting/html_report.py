#Renders a report dict (see report_data.build_report) as a standalone HTML page.
#
#One file, inline CSS, no external assets. Sober and typographic - meant to be
#attached to a ticket and read by an analyst, not shown on a dashboard. Adapts
#to the reader's light / dark preference and prints cleanly to paper or PDF.

import hashlib
import html
from typing import Any, Dict, List

_CSS = """
:root{
  --bg:#ffffff; --panel:#f7f8fa; --ink:#1a1d24; --soft:#5b6472; --line:#e2e6ec;
  --accent:#1f6feb; --crit:#c0203f; --high:#b5560d; --med:#8a6d0b; --low:#1c7a48;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0f1319; --panel:#161b23; --ink:#e6e9ef; --soft:#9aa4b2; --line:#262d38;
    --accent:#5b9bff; --crit:#ff5a78; --high:#e0913f; --med:#d8c05a; --low:#4fd08a;
  }
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink)}
body{font:14px/1.62 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
     padding:40px 20px}
.sheet{max-width:820px;margin:0 auto}
.mono{font-family:ui-monospace,"Cascadia Mono","JetBrains Mono",Consolas,monospace}

.masthead{display:flex;justify-content:space-between;align-items:flex-start;
  border-bottom:2px solid var(--ink);padding-bottom:14px;margin-bottom:8px}
.masthead h1{font-size:19px;font-weight:700;letter-spacing:.02em;margin:0}
.masthead .org{font-size:12px;color:var(--soft);margin-top:3px}
.masthead .ref{text-align:right;font-size:11.5px;color:var(--soft);line-height:1.7}
.masthead .ref b{color:var(--ink);font-weight:600}

.classbar{display:flex;gap:0;margin:16px 0 26px;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.classbar div{flex:1;padding:10px 14px;border-right:1px solid var(--line)}
.classbar div:last-child{border-right:0}
.classbar .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--soft)}
.classbar .val{font-size:15px;font-weight:700;margin-top:3px}
.sev-Critical{color:var(--crit)} .sev-High{color:var(--high)}
.sev-Medium{color:var(--med)} .sev-Low{color:var(--low)}

section{margin:26px 0}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--soft);
   margin:0 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
p{margin:0 0 10px}
.lead{font-size:14.5px;line-height:1.7}

table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.07em;
   color:var(--soft);font-weight:600;padding:6px 10px;border-bottom:1px solid var(--line)}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.k{color:var(--soft);white-space:nowrap;width:190px}
.tl td{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:11.5px}
.muted{color:var(--soft)}
a{color:var(--accent);text-decoration:none}

.note{background:var(--panel);border:1px solid var(--line);border-radius:6px;
  padding:12px 14px;font-size:13px;line-height:1.65}
.note .row{display:flex;gap:8px;margin:2px 0}
.note .row b{color:var(--soft);font-weight:600;min-width:150px}

footer{margin-top:36px;padding-top:12px;border-top:1px solid var(--line);
  font-size:10.5px;color:var(--soft);line-height:1.6}

.toolbar{max-width:820px;margin:0 auto 18px}
.toolbar button{font:inherit;font-size:12.5px;padding:7px 15px;border:1px solid var(--line);
  background:var(--panel);color:var(--ink);border-radius:6px;cursor:pointer}
@media print{
  body{padding:0;color:#000;background:#fff}
  :root{--ink:#000;--soft:#333;--line:#bbb;--bg:#fff;--panel:#f2f2f2}
  .toolbar{display:none}
  section{page-break-inside:avoid}
}
"""


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _pct(v: Any) -> str:
    try:
        return f"{round(float(v) * 100)}%"
    except (TypeError, ValueError):
        return "n/a"


def _ref_id(report: Dict[str, Any]) -> str:
    actor = report["attacker"]["actor"] or "unknown"
    gen = report["meta"]["generated_at"] or ""
    digest = hashlib.sha1(f"{actor}|{gen}".encode()).hexdigest()[:6].upper()
    date = (gen[:10] or "").replace("-", "")
    return f"ACT-{date}-{digest}"


def _table(headers: List[str], rows: List[List[str]], cls: str = "") -> str:
    if not rows:
        return '<p class="muted">None recorded.</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


# severity -> (fill, border) - light/dark aware pairs kept sober enough to print
_SEV_FILL = {
    "Critical": ("#fbe4e8", "#c0203f"),
    "High":     ("#fbe9db", "#b5560d"),
    "Medium":   ("#fbf3d6", "#8a6d0b"),
    "Low":      ("#dff2e7", "#1c7a48"),
}
_NOT_OBSERVED_FILL = ("#f2f3f5", "#b6bcc6")


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _flow_diagram(kill_chain: List[Dict[str, Any]], deepest_stage: int) -> str:
    """An inline SVG of the full kill chain, the attacker's reached stages
    highlighted by severity and labelled with the MITRE techniques observed
    at each one. No JS, no external assets - same philosophy as the rest of
    this report."""

    if not kill_chain:
        return '<p class="muted">No kill-chain activity recorded.</p>'

    n = len(kill_chain)
    box_w, box_h, gap, pad = 132, 76, 26, 8
    width = n * box_w + (n - 1) * gap + pad * 2
    height = box_h + pad * 2 + 16

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'style="max-width:{width}px;display:block;margin:0 auto" '
        f'xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-label="Attack flow across the kill chain">',
        '<defs><marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L8,4 L0,8 z" fill="var(--soft)"/></marker></defs>',
    ]

    y = pad
    for i, stage in enumerate(kill_chain):
        x = pad + i * (box_w + gap)
        observed = bool(stage.get("observed", True))
        is_deepest = observed and stage["stage"] == deepest_stage
        fill, border = _SEV_FILL.get(stage.get("severity", "Low"), _SEV_FILL["Low"]) \
            if observed else _NOT_OBSERVED_FILL

        if i > 0:
            prev_x = pad + (i - 1) * (box_w + gap) + box_w
            parts.append(
                f'<line x1="{prev_x}" y1="{y + box_h / 2}" x2="{x}" y2="{y + box_h / 2}" '
                f'stroke="var(--soft)" stroke-width="1.4" marker-end="url(#arrow)"/>'
            )

        stroke_w = 2.4 if is_deepest else 1.2
        dash = "0" if observed else "4 3"
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="7" '
            f'fill="{fill}" stroke="{border}" stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash}"/>'
        )
        parts.append(
            f'<text x="{x + box_w / 2}" y="{y + 18}" text-anchor="middle" '
            f'font-size="9.5" font-weight="700" fill="{border}" '
            f'style="text-transform:uppercase;letter-spacing:.04em">Stage {stage["stage"]}</text>'
        )
        parts.append(
            f'<text x="{x + box_w / 2}" y="{y + 33}" text-anchor="middle" '
            f'font-size="11" font-weight="600" fill="var(--ink)">'
            f'{_e(_truncate(stage["name"], 20))}</text>'
        )
        techniques = ", ".join(stage.get("techniques") or [])
        label = _e(_truncate(techniques, 22)) if techniques else ("not observed" if not observed else "—")
        parts.append(
            f'<text x="{x + box_w / 2}" y="{y + 49}" text-anchor="middle" '
            f'font-size="9" fill="var(--soft)" font-family="ui-monospace,Consolas,monospace">'
            f'{label}</text>'
        )
        if is_deepest:
            parts.append(
                f'<text x="{x + box_w / 2}" y="{y + box_h - 8}" text-anchor="middle" '
                f'font-size="8.5" font-weight="700" fill="{border}" '
                f'style="text-transform:uppercase;letter-spacing:.06em">▲ current</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


def render_html(report: Dict[str, Any]) -> str:
    meta = report["meta"]
    attacker = report["attacker"]
    risk = report["risk"]
    ai = report.get("ai")
    actions = report["actions_taken"]
    pred = report["prediction"]

    status = "Host compromised" if attacker["succeeded"] else "No confirmed compromise"
    decision_label = actions["decision"].replace("_", " ").upper()
    nxt = pred["next_steps"][0] if pred["next_steps"] else None

    classbar = "".join(
        f'<div><div class="lbl">{lbl}</div>'
        f'<div class="val{(" " + vc) if vc else ""}">{val}</div></div>'
        for lbl, val, vc in [
            ("Severity", _e(risk["severity"]), f'sev-{_e(risk["severity"])}'),
            ("Risk score", f'{_e(risk["score"])}/100', ""),
            ("Decision confidence", _pct(risk["decision_confidence"]), ""),
            ("Status", _e(status), "sev-Critical" if attacker["succeeded"] else ""),
        ]
    )

    facts_rows = [
        ("Attacker", f'<span class="mono">{_e(attacker["actor"])}</span>'),
        ("Monitored host", _e(meta["monitored_host"] or "not specified")),
        ("Activity window", f'{_e(attacker["first_activity"])} &ndash; {_e(attacker["last_activity"])}'),
        ("Kill-chain reach",
         f'Stage {_e(attacker["deepest_stage"])} of {_e(attacker["total_stages"])} '
         f'&nbsp;({_pct(attacker["completeness"])})'),
        ("Anomaly score", _pct(risk["anomaly_score"])),
        ("Response posture",
         "Autonomous response armed" if meta["auto_response_armed"] else "Simulation (not armed)"),
    ]
    facts = "<table>" + "".join(
        f'<tr><td class="k">{k}</td><td>{v}</td></tr>' for k, v in facts_rows
    ) + "</table>"

    mitre = _table(
        ["ID", "Technique", "Tactic"],
        [[f'<a href="{_e(t["url"])}">{_e(t["id"])}</a>', _e(t["name"]), _e(t["tactic"])]
         for t in report["mitre_techniques"]],
    )

    killchain = _table(
        ["Stage", "Phase", "Observed activity"],
        [[_e(k["stage"]), _e(k["name"]),
          (_e(", ".join(k["behaviors"])) +
           (f' <span class="muted">[{_e(", ".join(k["techniques"]))}]</span>' if k["techniques"] else ""))
          if k.get("observed", True) else '<span class="muted">Not observed</span>']
         for k in report["kill_chain"]],
    )

    flow_diagram = _flow_diagram(report["kill_chain"], attacker["deepest_stage"])

    timeline = _table(
        ["Time", "Event", "User", "Source", "Detail"],
        [[_e(r["time"]), _e(r["type"]), _e(r["user"] or "—"),
          _e(r["ip_address"] or "—"), _e(r["description"])]
         for r in report["timeline"]],
        cls="tl",
    )

    if ai:
        ai_block = f"""
      <div class="note">
        <div class="row"><b>Model verdict</b> {_e(ai.get("recommendation"))} &nbsp;&middot;&nbsp;
            assessed threat {_e(ai.get("threat") or "n/a")} &nbsp;&middot;&nbsp;
            model confidence {_pct(ai.get("confidence"))}</div>
        <div class="row"><b>Risk (statistical / AI)</b> {_e(ai.get("statistical_risk", risk["score"]))}/100
            &nbsp;&rarr;&nbsp; {_e(ai.get("ai_adjusted_risk", "—"))}/100</div>
        <div class="row"><b>Confidence blend</b> {_pct(ai.get("statistical_confidence"))}
            &nbsp;&rarr;&nbsp; {_pct(ai.get("blended_confidence", risk["decision_confidence"]))}</div>
        <div class="row"><b>Effect on decision</b> {_e(ai.get("influence", "advisory"))}</div>
        <div class="row"><b>Rationale</b> {_e(ai.get("reasoning") or "—")}</div>
      </div>"""
    else:
        ai_block = ('<p class="muted">No AI model was consulted; the assessment and '
                    'decision are from ACT’s deterministic engine alone.</p>')

    also = actions["also_consider"]
    also_block = ""
    if also:
        also_block = ("<p class=\"muted\" style=\"margin-top:10px\">Analyst should also consider:</p><ul>"
                      + "".join(f"<li>{_e(x)}</li>" for x in also) + "</ul>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_e(_ref_id(report))} &mdash; Incident Report</title>
<style>{_CSS}</style></head>
<body>
<div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="sheet">

  <div class="masthead">
    <div>
      <h1>Security Incident Report</h1>
      <div class="org">{_e(meta["tool"])}</div>
    </div>
    <div class="ref">
      <div><b>Reference</b> {_e(_ref_id(report))}</div>
      <div><b>Generated</b> {_e(meta["generated_at"])}</div>
      <div><b>Classification</b> Internal use</div>
    </div>
  </div>

  <div class="classbar">{classbar}</div>

  <section>
    <h2>1 &nbsp; Summary</h2>
    <p class="lead">{_e(report["summary"])}</p>
    {facts}
  </section>

  <section>
    <h2>2 &nbsp; Assessment</h2>
    <p>Deepest phase reached was <b>{_e(attacker["current_stage_name"] or "early-stage activity")}</b>.
       {"The attacker established a confirmed foothold on the host." if attacker["succeeded"]
        else "No successful authentication was confirmed."}
       {("Most likely next move: <b>" + _e(nxt["stage_name"]) + "</b> (" + _pct(nxt["probability"]) + ").") if nxt else ""}</p>
    {ai_block}
  </section>

  <section>
    <h2>3 &nbsp; MITRE ATT&amp;CK techniques</h2>
    {mitre}
  </section>

  <section>
    <h2>4 &nbsp; Attack flow &amp; kill-chain progression</h2>
    {flow_diagram}
    <p class="muted" style="margin-top:10px;font-size:11.5px">
      Solid boxes are stages this attacker reached, coloured by severity; dashed
      boxes were not observed. <b>▲ current</b> marks the deepest stage reached.
    </p>
    {killchain}
  </section>

  <section>
    <h2>5 &nbsp; Event timeline</h2>
    {timeline}
  </section>

  <section>
    <h2>6 &nbsp; Response</h2>
    <table>
      <tr><td class="k">Decision</td><td><b>{_e(decision_label)}</b> on {_e(actions["target"] or "n/a")}
          &nbsp;({_e(actions["urgency"])} urgency, {_pct(actions["confidence"])} confidence)</td></tr>
      <tr><td class="k">Rationale</td><td>{_e(actions["rationale"])}</td></tr>
      <tr><td class="k">Execution</td><td>{_e(actions["response_status"] or "n/a")}
          {"&nbsp;(carried out on the host)" if actions["response_armed"] else "&nbsp;(simulation only)"}</td></tr>
      <tr><td class="k">Command</td><td class="mono">{_e(actions["response_command"] or "n/a")}</td></tr>
    </table>
    {also_block}
  </section>

  <footer>
    Prepared automatically by {_e(meta["tool"])} v{_e(meta["version"])}. Point-in-time snapshot;
    findings reflect the evidence available at generation. ACT blocks source addresses
    autonomously above its confidence threshold; account lockout and host isolation are
    advisory and require analyst action.
  </footer>
</div>
</body></html>"""
