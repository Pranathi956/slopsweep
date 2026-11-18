# slopsweep

A small, **zero-dependency agent** that sweeps *any* codebase for:

| Category | What it finds |
|---|---|
| **security** | hardcoded secrets/keys/tokens, SQL injection patterns, `eval`/`exec`, `shell=True`, unsafe deserialization, disabled TLS verification, wildcard CORS, weak hashes, committed `.env`/key files, root Dockerfiles |
| **slop** | leftover AI chatter ("Here is the updated implementation"), truncated-generation placeholders (`# rest of code here`), obvious comments, commented-out code, debug prints/`console.log`, junk variable names, giant/deeply-nested functions, unused & wildcard imports |
| **coding-gap** | bare/swallowed exceptions, mutable default args, missing HTTP timeouts, empty catch blocks, `assert` for runtime checks, duplicate definitions, syntax errors, missing README/LICENSE/tests/lockfile |
| **loose-end** | `TODO/FIXME/HACK`, `NotImplementedError` stubs, empty functions, hardcoded localhost, linter suppressions, "temporary workaround" notes, backup/junk files |

**Architecture agnostic:** regex rules run on every text file (any language/framework);
Python gets deeper AST analysis; repo-level checks work on any layout. No framework, no cloud, no API key.

## Install & run (30 seconds)

```bash
git clone <this-repo> && cd slopsweep
python -m slopsweep .                 # no install needed (Python 3.9+)
# or
pip install -e . && slopsweep .
```

## Usage

```bash
slopsweep path/to/project                     # human-readable report
slopsweep . --agent                           # autonomous loop: plan -> sweep -> triage -> prioritise
slopsweep . -f html -o report.html            # shareable report (also: json, markdown, sarif)
slopsweep . -c security -s high               # only high+ security issues
slopsweep . --fail-on high                    # exit 1 for CI gating
slopsweep . --ignore "vendor/*" --ignore "*.generated.js"
```

Try the demo: `python -m slopsweep examples/vulnerable_app --agent`

## Suppressing findings

- Inline: `# slopsweep: ignore` or `# slopsweep: ignore[SEC007,LOS001]` (same or previous line)
- File: `.slopsweepignore` with glob patterns, one per line

## Design

```
scanner.py     walks files, applies rules, honours ignores, masks secrets in output
rules.py       language-agnostic regex rule table (id, category, severity, fix)
pyanalyzer.py  Python AST checks (exceptions, mutable defaults, stubs, unused imports...)
repo_checks.py repository hygiene (README, tests, .env, keys, Dockerfile)
agent.py       plan -> sweep -> triage (dedupe noise) -> prioritise loop
reporters.py   text | json | markdown | sarif (GitHub code scanning) | html
cli.py         argparse CLI, CI-friendly exit codes
```

Design choices: findings carry a concrete **fix** suggestion; secrets are **masked** in reports;
test files get downgraded severity; a **health score** (0-100) summarises a run; SARIF output plugs
straight into GitHub code scanning. Adding a rule = one line in `rules.py`.

## Tests

```bash
pip install pytest && pytest -q
```

## Limitations (honest)

Pattern-based heuristics can produce false positives/negatives — it's a fast first-pass linter,
not a replacement for a full SAST tool. Deep AST analysis is Python-only; other languages use regex rules.

## License

MIT
