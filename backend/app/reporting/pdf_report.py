#A tiny, dependency-free PDF writer - just enough for an analyst-ready incident
#report on a clean Python install (no reportlab / weasyprint to pip install).
#
#It lays a flat list of styled lines (and thin rules) onto Letter pages using
#the standard PostScript fonts, which every PDF reader has built in. The rich
#version of the report is the HTML one (html_report.py); this keeps the
#"Download PDF" button working everywhere and produces a clean, sober document.

from typing import Any, Dict, List, Tuple

PAGE_W, PAGE_H = 612, 792          #US Letter, points
MARGIN = 56
WRAP = 96                          #chars per wrapped body line

# style -> (font_resource, size, line_height, gap_before)
_STYLE = {
    "title":  ("F2", 17, 22, 0),
    "org":    ("F1", 9.5, 13, 2),
    "meta":   ("F3", 8.5, 12, 0),
    "h2":     ("F2", 10.5, 15, 16),
    "body":   ("F1", 9.5, 13, 0),
    "kv":     ("F1", 9.5, 13, 0),
    "mono":   ("F3", 8.3, 11.5, 0),
    "gap":    ("F1", 6, 6, 0),
}
_KEY_WIDTH = 22                    #chars reserved for a key in a "key: value" line


def _esc(text: str) -> str:
    return str(text).replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text: str, width: int, indent: int = 0) -> List[str]:
    text = str(text).replace("\t", "    ")
    pad = " " * indent
    out: List[str] = []
    for raw in text.split("\n"):
        words, cur = raw.split(" "), ""
        for word in words:
            while len(word) > width:
                if cur:
                    out.append(cur); cur = ""
                out.append((pad + word[:width]) if out or pad else word[:width])
                word = word[width:]
            cand = f"{cur} {word}".strip() if cur else word
            if len(cand) + (len(pad) if out else 0) <= width:
                cur = cand
            else:
                out.append((pad + cur) if out else cur)
                cur = word
        out.append((pad + cur) if out else cur)
    return out or [""]


class _Doc:

    def __init__(self) -> None:
        self._items: List[Tuple[str, str]] = []   # (style, text)  |  ("rule", "")

    def add(self, style: str, text: str = "") -> None:
        if style in ("title", "org", "meta", "h2", "rule"):
            self._items.append((style, str(text)))
            return
        first = True
        for chunk in _wrap(text, WRAP if style != "mono" else 108):
            self._items.append((style, chunk))
            first = False

    def kv(self, key: str, value: str) -> None:
        label = f"{key}:".ljust(_KEY_WIDTH)
        wrapped = _wrap(str(value), WRAP - _KEY_WIDTH)
        self._items.append(("kv", label + wrapped[0]))
        for extra in wrapped[1:]:
            self._items.append(("kv", " " * _KEY_WIDTH + extra))

    def row(self, cols: List[str], widths: List[int]) -> None:
        cells = [str(c) for c in cols]
        cells = [c if len(c) <= w - 1 else c[: w - 2] + "…" for c, w in zip(cells, widths)]
        line = "".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()
        self._items.append(("mono", line[:118]))

    def gap(self) -> None:
        self._items.append(("gap", ""))

    def rule(self) -> None:
        self._items.append(("rule", ""))

    # ------------------------------------------------------------------ #

    def _paginate(self):
        pages: List[List[tuple]] = []
        page: List[tuple] = []
        y = PAGE_H - MARGIN

        for style, text in self._items:
            if style == "rule":
                if y - 8 < MARGIN:
                    pages.append(page); page = []; y = PAGE_H - MARGIN
                y -= 5
                page.append(("__rule__", y))
                y -= 8
                continue

            font, size, lh, gap_before = _STYLE[style]
            if gap_before:
                y -= gap_before
            if y - lh < MARGIN:
                pages.append(page); page = []; y = PAGE_H - MARGIN
            page.append(("__text__", font, size, y - size, text))
            y -= lh

        if page:
            pages.append(page)
        return pages or [[]]

    def to_bytes(self) -> bytes:
        pages = self._paginate()
        n = len(pages)

        objects: List[bytes] = []
        page_ids = list(range(3, 3 + n))
        content_ids = list(range(3 + n, 3 + 2 * n))
        font_ids = list(range(3 + 2 * n, 6 + 2 * n))

        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        kids = " ".join(f"{p} 0 R" for p in page_ids)
        objects.append(f"<< /Type /Pages /Count {n} /Kids [{kids}] >>".encode("latin-1"))

        resources = (f"<< /Font << /F1 {font_ids[0]} 0 R /F2 {font_ids[1]} 0 R "
                     f"/F3 {font_ids[2]} 0 R >> >>")
        for i in range(n):
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                f"/Resources {resources} /Contents {content_ids[i]} 0 R >>".encode("latin-1")
            )

        for lines in pages:
            parts: List[str] = []
            text_open = False
            for item in lines:
                if item[0] == "__rule__":
                    if text_open:
                        parts.append("ET"); text_open = False
                    y = item[1]
                    parts.append(f"0.6 w 0.6 0.6 0.6 RG {MARGIN} {y:.1f} m {PAGE_W - MARGIN} {y:.1f} l S")
                else:
                    _, font, size, baseline, text = item
                    if not text_open:
                        parts.append("BT"); text_open = True
                    parts.append(
                        f"/{font} {size:.1f} Tf 0 0 0 rg 1 0 0 1 {MARGIN:.1f} {baseline:.1f} Tm "
                        f"({_esc(text)}) Tj"
                    )
            if text_open:
                parts.append("ET")
            stream = "\n".join(parts).encode("latin-1", "replace")
            objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                           + stream + b"\nendstream")

        for base_font in (b"Helvetica", b"Helvetica-Bold", b"Courier"):
            objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /" + base_font
                           + b" /Encoding /WinAnsiEncoding >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for idx, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{idx} 0 obj\n".encode("latin-1") + body + b"\nendobj\n"

        xref_pos = len(out)
        total = len(objects) + 1
        out += f"xref\n0 {total}\n".encode("latin-1")
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode("latin-1")
        out += (f"trailer\n<< /Size {total} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF").encode("latin-1")
        return bytes(out)


# ---------------------------------------------------------------------- #


def _pct(v: Any) -> str:
    try:
        return f"{round(float(v) * 100)}%"
    except (TypeError, ValueError):
        return "n/a"


def _ref_id(report: Dict[str, Any]) -> str:
    import hashlib
    actor = report["attacker"]["actor"] or "unknown"
    gen = report["meta"]["generated_at"] or ""
    digest = hashlib.sha1(f"{actor}|{gen}".encode()).hexdigest()[:6].upper()
    return f"ACT-{(gen[:10] or '').replace('-', '')}-{digest}"


def render_pdf(report: Dict[str, Any]) -> bytes:
    meta = report["meta"]
    attacker = report["attacker"]
    risk = report["risk"]
    ai = report.get("ai")
    actions = report["actions_taken"]
    pred = report["prediction"]
    nxt = pred["next_steps"][0] if pred["next_steps"] else None

    d = _Doc()
    d.add("title", "Security Incident Report")
    d.add("org", meta["tool"])
    d.add("meta", f"Reference {_ref_id(report)}    Generated {meta['generated_at']}    "
                  f"Classification: Internal use")
    d.rule()

    status = "HOST COMPROMISED" if attacker["succeeded"] else "No confirmed compromise"
    d.add("body", f"Severity {risk['severity']}  |  Risk {risk['score']}/100  |  "
                  f"Decision confidence {_pct(risk['decision_confidence'])}  |  {status}")
    d.gap()

    d.add("h2", "1   SUMMARY")
    d.add("body", report["summary"] or "n/a")
    d.gap()
    d.kv("Attacker", attacker["actor"])
    d.kv("Monitored host", meta["monitored_host"] or "not specified")
    d.kv("Activity window", f"{attacker['first_activity']}  to  {attacker['last_activity']}")
    d.kv("Kill-chain reach", f"stage {attacker['deepest_stage']} of {attacker['total_stages']} "
                             f"({_pct(attacker['completeness'])})")
    d.kv("Anomaly score", _pct(risk["anomaly_score"]))
    d.kv("Response posture", "autonomous response armed" if meta["auto_response_armed"]
                             else "simulation (not armed)")

    d.add("h2", "2   ASSESSMENT")
    d.add("body", f"Deepest phase reached was {attacker['current_stage_name'] or 'early-stage activity'}. "
                  + ("The attacker established a confirmed foothold on the host. "
                     if attacker["succeeded"] else "No successful authentication was confirmed. ")
                  + (f"Most likely next move: {nxt['stage_name']} ({_pct(nxt['probability'])})." if nxt else ""))
    d.gap()
    if ai:
        d.kv("Model verdict", f"{ai.get('recommendation')} - threat {ai.get('threat') or 'n/a'} - "
                              f"confidence {_pct(ai.get('confidence'))}")
        d.kv("Risk stat / AI", f"{ai.get('statistical_risk', risk['score'])}/100  ->  "
                               f"{ai.get('ai_adjusted_risk', '-')}/100")
        d.kv("Confidence blend", f"{_pct(ai.get('statistical_confidence'))}  ->  "
                                 f"{_pct(ai.get('blended_confidence', risk['decision_confidence']))}")
        d.kv("Effect on decision", ai.get("influence", "advisory"))
        d.kv("Rationale", ai.get("reasoning") or "-")
    else:
        d.add("body", "No AI model was consulted; the assessment and decision are from ACT's "
                      "deterministic engine alone.")

    d.add("h2", "3   MITRE ATT&CK TECHNIQUES")
    if report["mitre_techniques"]:
        d.row(["ID", "TECHNIQUE", "TACTIC"], [14, 46, 30])
        for t in report["mitre_techniques"]:
            d.row([t["id"], t["name"], t["tactic"]], [14, 46, 30])
    else:
        d.add("body", "None recorded.")

    d.add("h2", "4   KILL-CHAIN PROGRESSION")
    if report["kill_chain"]:
        d.row(["ST", "PHASE", "OBSERVED ACTIVITY"], [4, 24, 62])
        for k in report["kill_chain"]:
            activity = ", ".join(k["behaviors"])
            if k["techniques"]:
                activity += f"  [{', '.join(k['techniques'])}]"
            d.row([str(k["stage"]), k["name"], activity], [4, 24, 62])
    else:
        d.add("body", "None recorded.")

    d.add("h2", "5   EVENT TIMELINE")
    d.row(["TIME", "EVENT", "USER", "SOURCE", "DETAIL"], [21, 17, 10, 16, 44])
    for r in report["timeline"]:
        d.row([r["time"] or "", r["type"] or "", r["user"] or "-",
               r["ip_address"] or "-", r["description"] or ""], [21, 17, 10, 16, 44])

    d.add("h2", "6   RESPONSE")
    d.kv("Decision", f"{actions['decision'].replace('_', ' ').upper()} on {actions['target'] or 'n/a'} "
                     f"({actions['urgency']} urgency, {_pct(actions['confidence'])} confidence)")
    d.kv("Rationale", actions["rationale"])
    d.kv("Execution", f"{actions['response_status'] or 'n/a'}"
                      + (" (carried out on the host)" if actions["response_armed"] else " (simulation only)"))
    d.kv("Command", actions["response_command"] or "n/a")
    if actions["also_consider"]:
        d.add("body", "Analyst should also consider:")
        for tip in actions["also_consider"]:
            d.add("body", f"  - {tip}")

    d.gap()
    d.rule()
    d.add("meta", f"Prepared automatically by {meta['tool']} v{meta['version']}. Point-in-time snapshot. "
                  f"ACT blocks source addresses autonomously above its confidence threshold; account "
                  f"lockout and host isolation are advisory.")

    return d.to_bytes()
