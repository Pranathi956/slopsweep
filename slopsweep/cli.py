"""Command line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .models import GAP, LOOSE_END, SECURITY, SLOP, Severity
from .reporters import FORMATS, to_text
from .scanner import scan

CATS = {"security": SECURITY, "slop": SLOP, "gaps": GAP, "loose-ends": LOOSE_END}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="slopsweep",
        description="Agent that sweeps any codebase for security issues, AI slop, coding gaps and loose ends.")
    p.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    p.add_argument("-f", "--format", choices=sorted(FORMATS), default="text")
    p.add_argument("-o", "--output", help="write report to this file instead of stdout")
    p.add_argument("-s", "--min-severity", default="info", help="info|low|medium|high|critical")
    p.add_argument("-c", "--category", action="append", choices=sorted(CATS),
                   help="limit to category (repeatable)")
    p.add_argument("--ignore", action="append", default=[], help="glob to ignore (repeatable)")
    p.add_argument("--fail-on", default=None, help="exit 1 if any finding >= this severity")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--agent", action="store_true", help="run the autonomous agent loop (plan, sweep, triage, report)")
    p.add_argument("-V", "--version", action="version", version=f"slopsweep {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        min_sev = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cats = {CATS[c] for c in args.category} if args.category else None

    if args.agent:
        from .agent import run_agent
        result = run_agent(args.path, args.ignore, min_sev, cats, log=lambda m: print(m, file=sys.stderr))
    else:
        result = scan(args.path, args.ignore, min_sev, cats)

    if args.format == "text":
        report = to_text(result, color=(sys.stdout.isatty() and not args.no_color and not args.output))
    else:
        report = FORMATS[args.format](result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
