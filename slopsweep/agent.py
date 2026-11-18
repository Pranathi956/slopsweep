"""Autonomous agent loop: plan -> sweep -> triage -> prioritise -> report.

Fully offline and deterministic (no API key needed). The agent inspects the repo
to decide *what* to scan, scans, then triages findings into an action plan.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from .models import Finding, ScanResult, Severity
from .scanner import iter_files, scan


def _plan(root: Path, ignores: list[str]) -> dict:
    files = iter_files(root, ignores) if root.is_dir() else [root]
    langs = Counter(p.suffix.lower() or p.name for p in files)
    return {"files": len(files), "top_types": langs.most_common(5)}


def _triage(findings: list[Finding]) -> list[Finding]:
    """Collapse noisy repeats: keep at most 5 of the same rule per file, annotate the rest."""
    seen: Counter = Counter()
    out: list[Finding] = []
    suppressed: Counter = Counter()
    for f in findings:
        key = (f.rule_id, f.file)
        seen[key] += 1
        if seen[key] <= 5:
            out.append(f)
        else:
            suppressed[key] += 1
    for (rid, file), n in suppressed.items():
        first = next(f for f in out if f.rule_id == rid and f.file == file)
        first.message += f" (+{n} more in this file)"
    return out


def run_agent(path: str, ignores: list[str], min_sev: Severity, cats: set[str] | None,
              log: Callable[[str], None] = lambda m: None) -> ScanResult:
    root = Path(path).resolve()
    log(f"[agent] planning: inspecting {root}")
    plan = _plan(root, ignores)
    log(f"[agent] {plan['files']} files; dominant types: {plan['top_types']}")
    log("[agent] sweeping: security, slop, coding gaps, loose ends")
    result = scan(root, ignores, min_sev, cats)
    log(f"[agent] raw findings: {len(result.findings)}")
    result.findings = _triage(result.findings)
    log(f"[agent] after triage: {len(result.findings)}")
    crit = [f for f in result.findings if f.severity >= Severity.HIGH]
    if crit:
        log(f"[agent] priority: fix these {len(crit)} high/critical issues first:")
        for f in crit[:10]:
            log(f"[agent]   - {f.file}:{f.line} {f.rule_id} {f.message}")
    else:
        log("[agent] no high/critical issues. nice.")
    log(f"[agent] done. health score {result.score()}/100")
    return result
