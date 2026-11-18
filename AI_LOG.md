# AI Log

An honest record of how AI was used on this project.

## Tools used
- **Claude (Anthropic)** in a Claude Code session: planning, code generation, tests, documentation and debugging help.

## Who did what
- **Pranathi** received the hackathon brief, chose to build the project, ran every command on her own Windows machine, checked the outputs, created the GitHub repo, and pushed it.
- **Claude** wrote the first version of the code, tests, README, CI workflow and this log, and answered setup and Git questions.

## How the project came together
1. **Brief to design.** The brief asked for a simple, architecture-agnostic agent for security, slop, coding gaps and loose ends. Claude proposed a zero-dependency scanner: language-agnostic regex rules, AST analysis for Python, and repository-level checks.
2. **Build.** Claude wrote the scanner, rules, Python analyzer, repo checks, agent loop (plan, sweep, triage, prioritise), five report formats, a CLI and 29 tests.
3. **Self-testing.** The tool was run on its own source. That exposed real issues (an unused import, an operator-precedence bug in an unused-import helper) and false positives (assert statements in test files, rule definitions matching their own patterns), which were fixed.
4. **HTTP API.** After the platform's grader style came up, Claude added `GET /health` and `POST /scan` using only the standard library, with input validation and filename sanitising, plus 13 tests.
5. **Verification by the author.** Pranathi ran the tests, the demo scan and the HTML report locally and compared them with the expected outputs.

## Where the AI got things wrong
- **Wrong score claim.** Claude first reported a demo health score of 96/100. That was the scanner's score on its own code; the demo app actually scores 0/100. Caught and corrected during local verification.
- **Shell syntax.** Claude gave Linux-only commands (`/dev/null`, `$?`) that failed in PowerShell. Replaced with PowerShell equivalents.
- **`.gitignore` bug.** A `report.*` rule also ignored `docs/report.png`, so the screenshot would not commit. Fixed by anchoring it to `/report.*`.
- **False positives in the tool itself.** The scanner flagged its own rule table and test assertions until filters and a `.slopsweepignore` file were added.

## What was checked by a human
- All tests pass locally (`python -m pytest -q`).
- Demo output matches the expected counts (36 findings, score 0/100 on the intentionally vulnerable demo app).
- The tool scans its own repo clean (`python -m slopsweep .`).
- `GET /health` and `POST /scan` were called against a running server.

## Known limits
Pattern-based rules give false positives and negatives. Deep analysis exists only for Python. This is a fast first-pass linter, not a replacement for a full SAST tool.
