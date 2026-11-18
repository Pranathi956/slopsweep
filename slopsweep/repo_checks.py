"""Repository-level hygiene checks (architecture agnostic)."""
from __future__ import annotations

from pathlib import Path

from .models import GAP, LOOSE_END, SECURITY, Finding, Severity

ENV_FILES = {".env", ".env.local", ".env.production", ".env.prod"}
KEY_FILES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
KEY_EXTS = {".pem", ".p12", ".pfx", ".keystore", ".jks"}


def check_repo(root: Path, files: list[Path]) -> list[Finding]:
    out: list[Finding] = []
    names = {p.name.lower() for p in files}
    def rel(p: Path) -> str:
        return str(p.relative_to(root))

    def add(rid, cat, sev, msg, file, fix):
        out.append(Finding(rid, cat, sev, msg, file, 0, "", fix))

    if not any(n.startswith("readme") for n in names):
        add("REP001", GAP, Severity.MEDIUM, "No README found", ".", "Add a README explaining setup and usage.")
    if not any(n.startswith("license") or n.startswith("copying") for n in names):
        add("REP002", GAP, Severity.LOW, "No LICENSE file", ".", "Add a LICENSE (e.g. MIT).")
    if ".gitignore" not in names:
        add("REP003", GAP, Severity.LOW, "No .gitignore", ".", "Add a .gitignore for your stack.")

    code = [p for p in files if p.suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rs", ".rb", ".php"}]
    if len(code) >= 3:
        has_tests = any(
            "test" in p.name.lower() or any(part in {"tests", "test", "__tests__", "spec"} for part in p.parts)
            for p in code
        )
        on_disk = any((root / d).is_dir() for d in ("tests", "test", "__tests__", "spec"))
        if not has_tests and not on_disk:
            add("REP004", GAP, Severity.MEDIUM, "Code present but no tests found", ".", "Add automated tests.")

    manifests = {"requirements.txt", "pyproject.toml", "package.json", "go.mod", "cargo.toml", "pom.xml",
                 "build.gradle", "gemfile", "composer.json", "pipfile"}
    if any(p.suffix == ".py" for p in code) and not names & manifests:
        add("REP005", GAP, Severity.LOW, "Python code but no dependency manifest", ".",
            "Add requirements.txt or pyproject.toml.")

    if "package.json" in names and not names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}:
        add("REP006", GAP, Severity.LOW, "package.json without a lockfile", ".", "Commit a lockfile for reproducible installs.")

    for p in files:
        n = p.name.lower()
        if n in ENV_FILES:
            add("REP010", SECURITY, Severity.HIGH, f"Environment file committed: {rel(p)}", rel(p),
                "Remove from git history and add to .gitignore; commit .env.example instead.")
        if n in KEY_FILES or p.suffix.lower() in KEY_EXTS:
            add("REP011", SECURITY, Severity.CRITICAL, f"Key/cert file committed: {rel(p)}", rel(p),
                "Remove, rotate, and gitignore it.")
        if n.endswith((".bak", ".orig", ".old", ".tmp", "~")) or n in {".ds_store", "thumbs.db"}:
            add("REP020", LOOSE_END, Severity.LOW, f"Junk/backup file committed: {rel(p)}", rel(p), "Delete it.")
        if n in {"dockerfile"}:
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            if "USER " not in text:
                add("REP030", SECURITY, Severity.MEDIUM, "Dockerfile runs as root (no USER directive)", rel(p),
                    "Add a non-root USER.")
            if ":latest" in text:
                add("REP031", GAP, Severity.LOW, "Dockerfile uses unpinned ':latest' image", rel(p), "Pin the image version.")

    gi = next((p for p in files if p.name == ".gitignore"), None)
    if gi is not None:
        try:
            content = gi.read_text(errors="ignore")
        except OSError:
            content = ""
        if ".env" not in content and any(p.name.lower() in ENV_FILES for p in files):
            add("REP012", SECURITY, Severity.MEDIUM, ".gitignore does not exclude .env", rel(gi), "Add `.env` to .gitignore.")
    return out
