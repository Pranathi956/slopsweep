"""Output formats: text, json, markdown, sarif, html."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .models import ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;95m", Severity.HIGH: "\033[91m", Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m", Severity.INFO: "\033[90m",
}
RESET = "\033[0m"


def to_text(r: ScanResult, color: bool = False) -> str:
    out = []
    for f in r.findings:
        c, z = (COLORS[f.severity], RESET) if color else ("", "")
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"{c}[{f.severity.name:<8}]{z} {f.rule_id} {loc}\n    {f.message}")
        if f.snippet:
            out.append(f"    > {f.snippet}")
        if f.fix:
            out.append(f"    fix: {f.fix}")
    out.append("")
    out.append(_summary(r))
    return "\n".join(out)


def _summary(r: ScanResult) -> str:
    sev = ", ".join(f"{k}={v}" for k, v in r.counts_by_severity().items() if v)
    cat = ", ".join(f"{k}={v}" for k, v in sorted(r.counts_by_category().items()))
    return (f"slopsweep: {r.files_scanned} files, {len(r.findings)} findings "
            f"({sev or 'none'}) [{cat or 'clean'}]  health score: {r.score()}/100")


def to_json(r: ScanResult) -> str:
    return json.dumps({
        "root": r.root, "files_scanned": r.files_scanned, "score": r.score(),
        "by_severity": r.counts_by_severity(), "by_category": r.counts_by_category(),
        "findings": [f.to_dict() for f in r.findings],
    }, indent=2)


def to_markdown(r: ScanResult) -> str:
    lines = ["# slopsweep report", "",
             f"- **Files scanned:** {r.files_scanned}",
             f"- **Findings:** {len(r.findings)}",
             f"- **Health score:** {r.score()}/100", "",
             "| Severity | Count |", "|---|---|"]
    for k, v in r.counts_by_severity().items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "| Category | Count |", "|---|---|"]
    for k, v in sorted(r.counts_by_category().items()):
        lines.append(f"| {k} | {v} |")
    for cat in sorted(r.counts_by_category()):
        lines += ["", f"## {cat}", ""]
        for f in (x for x in r.findings if x.category == cat):
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            lines.append(f"- **{f.severity.name}** `{f.rule_id}` {loc} — {f.message}"
                         + (f"  \n  _Fix:_ {f.fix}" if f.fix else ""))
    return "\n".join(lines) + "\n"


def to_sarif(r: ScanResult) -> str:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
             Severity.LOW: "note", Severity.INFO: "note"}
    rules = {}
    for f in r.findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.message},
                                     "properties": {"category": f.category}})
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "slopsweep", "version": "1.0.0", "rules": list(rules.values())}},
            "results": [{
                "ruleId": f.rule_id, "level": level[f.severity],
                "message": {"text": f.message + (f" Fix: {f.fix}" if f.fix else "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)}}}],
            } for f in r.findings],
        }],
    }, indent=2)


def to_html(r: ScanResult) -> str:
    badge = {"CRITICAL": "#a21caf", "HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#0891b2", "INFO": "#6b7280"}
    rows = []
    for f in r.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        rows.append(
            f"<tr><td><span class='b' style='background:{badge[f.severity.name]}'>{f.severity.name}</span></td>"
            f"<td>{html.escape(f.category)}</td><td><code>{f.rule_id}</code></td>"
            f"<td><code>{html.escape(loc)}</code></td><td>{html.escape(f.message)}"
            f"<br><small>{html.escape(f.fix)}</small></td></tr>")
    sev = "".join(f"<li>{k}: <b>{v}</b></li>" for k, v in r.counts_by_severity().items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>slopsweep report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
.b{{color:#fff;padding:2px 8px;border-radius:10px;font-size:.75rem}}.score{{font-size:2.5rem;font-weight:700}}
ul{{display:flex;gap:1.5rem;list-style:none;padding:0}}</style></head><body>
<h1>slopsweep report</h1><div class="score">{r.score()}/100</div>
<p>{r.files_scanned} files scanned &middot; {len(r.findings)} findings &middot; {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>
<ul>{sev}</ul><table><tr><th>Severity</th><th>Category</th><th>Rule</th><th>Location</th><th>Issue / Fix</th></tr>
{''.join(rows)}</table></body></html>"""


FORMATS = {"text": to_text, "json": to_json, "markdown": to_markdown, "sarif": to_sarif, "html": to_html}
