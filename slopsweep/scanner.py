"""File walking + orchestration."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from .models import Finding, ScanResult, Severity
from .pyanalyzer import analyze_python
from .repo_checks import check_repo
from .rules import RULES

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".idea",
             ".vscode", ".mypy_cache", ".pytest_cache", ".tox", "target", "vendor", ".next", "site-packages",
             ".egg-info"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2",
             ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".pyc", ".so", ".dll", ".exe", ".bin", ".class",
             ".jar", ".lock", ".svg", ".min.js", ".map", ".sqlite", ".db"}
MAX_BYTES = 1_000_000
IGNORE_INLINE = re.compile(r"slopsweep:\s*ignore(?:\[([A-Z0-9_,\s]+)\])?", re.I)


def _load_ignore_file(root: Path) -> list[str]:
    f = root / ".slopsweepignore"
    if not f.is_file():
        return []
    return [ln.strip() for ln in f.read_text(errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")]


def iter_files(root: Path, extra_ignores: list[str]) -> list[Path]:
    out: list[Path] = []
    patterns = _load_ignore_file(root) + list(extra_ignores)
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts[:-1]):
            continue
        if p.suffix.lower() in SKIP_EXTS or p.name.endswith(".min.js"):
            continue
        relstr = rel.as_posix()
        if any(fnmatch.fnmatch(relstr, pat) or fnmatch.fnmatch(p.name, pat) or relstr.startswith(pat.rstrip("/") + "/")
               for pat in patterns):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:2048]


def _suppressed(line: str, rule_id: str) -> bool:
    m = IGNORE_INLINE.search(line)
    if not m:
        return False
    ids = m.group(1)
    if not ids:
        return True
    return rule_id in {i.strip().upper() for i in ids.split(",")}


def scan_file(path: Path, root: Path) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if _is_binary(data):
        return []
    text = data.decode("utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    ext = path.suffix.lower()
    lines = text.splitlines()
    findings: list[Finding] = []
    in_tests = any(part in {"tests", "test", "__tests__", "spec", "fixtures"} for part in path.parts) \
        or path.name.startswith("test_")
    is_doc = ext in {".md", ".rst", ".txt"}

    for rule in RULES:
        if rule.exts is not None and ext not in rule.exts:
            continue
        # secrets in docs/tests are usually examples: downgrade by skipping non-critical
        if is_doc and not rule.id.startswith("SEC00"):
            continue
        for i, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            if not rule.pattern.search(line):
                continue
            if rule.ignore and rule.ignore.search(line):
                continue
            if _suppressed(line, rule.id) or (i > 1 and _suppressed(lines[i - 2], rule.id)):
                continue
            sev = rule.severity
            if in_tests and sev >= Severity.MEDIUM:
                sev = Severity(sev - 1)
            findings.append(Finding(rule.id, rule.category, sev, rule.message, rel, i,
                                    _mask(line.strip())[:160], rule.fix))

    if ext == ".py":
        for f in analyze_python(rel, text):
            if in_tests and f.rule_id in {"PY033", "PY024"}:
                continue  # asserts and missing docstrings are normal in tests
            if f.line and 0 < f.line <= len(lines) and (
                _suppressed(lines[f.line - 1], f.rule_id)
                or (f.line > 1 and _suppressed(lines[f.line - 2], f.rule_id))
            ):
                continue
            findings.append(f)
    return _dedupe(findings)


_SECRET_MASK = re.compile(r"""(['"])([A-Za-z0-9_\-/+=\.]{8})[A-Za-z0-9_\-/+=\.]{4,}(\1)""")


def _mask(line: str) -> str:
    """Don't echo whole secrets into reports."""
    return _SECRET_MASK.sub(lambda m: f"{m.group(1)}{m.group(2)}…[masked]{m.group(3)}", line)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(root: str | Path, ignores: list[str] | None = None, min_severity: Severity = Severity.INFO,
         categories: set[str] | None = None) -> ScanResult:
    rootp = Path(root).resolve()
    if rootp.is_file():
        files, base = [rootp], rootp.parent
    else:
        files, base = iter_files(rootp, ignores or []), rootp
    result = ScanResult(root=str(rootp), files_scanned=len(files))
    for p in files:
        result.findings.extend(scan_file(p, base))
    if rootp.is_dir():
        result.findings.extend(check_repo(base, files))
    result.findings = [
        f for f in result.findings
        if f.severity >= min_severity and (not categories or f.category in categories)
    ]
    result.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    return result
