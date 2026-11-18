import json
import subprocess
import sys
from pathlib import Path

import pytest

from slopsweep.models import Severity
from slopsweep.pyanalyzer import analyze_python
from slopsweep.reporters import FORMATS
from slopsweep.scanner import scan, scan_file

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "vulnerable_app"


def ids(findings):
    return {f.rule_id for f in findings}


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


# ---- secrets -------------------------------------------------------------
def test_detects_aws_key(tmp_path):
    p = write(tmp_path, "a.txt", "key = AKIAABCDEFGHIJKLMNOP\n")
    assert "SEC001" in ids(scan_file(p, tmp_path))


def test_detects_hardcoded_password(tmp_path):
    p = write(tmp_path, "a.py", 'password = "SuperSecret123"\n')
    assert "SEC007" in ids(scan_file(p, tmp_path))


def test_placeholder_password_ignored(tmp_path):
    p = write(tmp_path, "a.py", 'password = os.environ["PASSWORD"]\napi_key = "your_api_key_here"\n')
    assert "SEC007" not in ids(scan_file(p, tmp_path))


def test_secret_is_masked_in_snippet(tmp_path):
    p = write(tmp_path, "a.py", 'password = "SuperSecret123456"\n')
    f = [x for x in scan_file(p, tmp_path) if x.rule_id == "SEC007"][0]
    assert "SuperSecret123456" not in f.snippet


# ---- python AST ----------------------------------------------------------
def test_python_gaps():
    src = (
        "import os\n"
        "def f(x=[]):\n    pass\n"
        "def g():\n    try:\n        1\n    except Exception:\n        pass\n"
        "def h():\n    try:\n        1\n    except:\n        raise\n"
    )
    got = ids(analyze_python("x.py", src))
    assert {"PY020", "PY021", "PY031", "PY030", "PY011"} <= got


def test_subprocess_shell_true():
    src = "import subprocess\nsubprocess.run('ls', shell=True)\n"
    assert "PY004" in ids(analyze_python("x.py", src))


def test_eval_constant_is_ok():
    assert "PY001" not in ids(analyze_python("x.py", "eval('1+1')\n"))


def test_syntax_error_reported():
    assert "PY000" in ids(analyze_python("x.py", "def (:\n"))


def test_used_import_not_flagged():
    assert "PY011" not in ids(analyze_python("x.py", "import os\nprint(os.name)\n"))


# ---- slop / loose ends ---------------------------------------------------
def test_ai_chatter(tmp_path):
    p = write(tmp_path, "a.js", "// Here is the updated implementation\nlet a = 1;\n")
    assert "SLP001" in ids(scan_file(p, tmp_path))


def test_truncation_placeholder(tmp_path):
    p = write(tmp_path, "a.js", "// ... rest of the code here\n")
    assert "SLP004" in ids(scan_file(p, tmp_path))


def test_todo(tmp_path):
    p = write(tmp_path, "a.go", "// TODO: fix this\n")
    assert "LOS001" in ids(scan_file(p, tmp_path))


def test_inline_ignore(tmp_path):
    p = write(tmp_path, "a.py", 'password = "SuperSecret123"  # slopsweep: ignore\n')
    assert "SEC007" not in ids(scan_file(p, tmp_path))


def test_inline_ignore_specific_rule(tmp_path):
    p = write(tmp_path, "a.py", 'password = "SuperSecret123"  # slopsweep: ignore[SEC999]\n')
    assert "SEC007" in ids(scan_file(p, tmp_path))


def test_js_empty_catch(tmp_path):
    p = write(tmp_path, "a.js", "try { x() } catch (e) {}\n")
    assert "GAP001" in ids(scan_file(p, tmp_path))


# ---- repo ----------------------------------------------------------------
def test_repo_checks(tmp_path):
    write(tmp_path, ".env", "A=1\n")
    write(tmp_path, "a.py", "x = 1\n")
    got = ids(scan(tmp_path).findings)
    assert {"REP001", "REP002", "REP010", "REP003"} <= got


def test_skips_node_modules(tmp_path):
    d = tmp_path / "node_modules" / "x"
    d.mkdir(parents=True)
    (d / "a.js").write_text("// TODO: x\n")
    assert not any(f.file.startswith("node_modules") for f in scan(tmp_path).findings)


def test_slopsweepignore(tmp_path):
    write(tmp_path, ".slopsweepignore", "gen/\n")
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "a.js").write_text("// TODO: x\n")
    assert not any(f.file.startswith("gen") for f in scan(tmp_path).findings)


# ---- whole demo / reporters / cli ---------------------------------------
def test_demo_app_is_flagged_hard():
    r = scan(DEMO)
    assert r.counts_by_severity()["CRITICAL"] >= 1
    assert r.score() < 50
    assert {"security", "slop", "coding-gap", "loose-end"} <= set(r.counts_by_category())


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_all_formats_render(fmt):
    out = FORMATS[fmt](scan(DEMO))
    assert out.strip()


def test_json_and_sarif_valid():
    r = scan(DEMO)
    assert json.loads(FORMATS["json"](r))["findings"]
    assert json.loads(FORMATS["sarif"](r))["runs"][0]["results"]


def test_min_severity_filter():
    r = scan(DEMO, min_severity=Severity.HIGH)
    assert r.findings and all(f.severity >= Severity.HIGH for f in r.findings)


def test_cli_fail_on_exit_code():
    cmd = [sys.executable, "-m", "slopsweep", str(DEMO), "--fail-on", "high", "--no-color"]
    assert subprocess.run(cmd, cwd=ROOT, capture_output=True).returncode == 1


def test_cli_clean_dir_exit_zero(tmp_path):
    write(tmp_path, "README.md", "# hi\n")
    write(tmp_path, "LICENSE", "MIT\n")
    write(tmp_path, ".gitignore", "x\n")
    cmd = [sys.executable, "-m", "slopsweep", str(tmp_path), "--fail-on", "low"]
    assert subprocess.run(cmd, cwd=ROOT, capture_output=True).returncode == 0


def test_agent_mode_runs(tmp_path):
    cmd = [sys.executable, "-m", "slopsweep", str(DEMO), "--agent"]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert "[agent] planning" in p.stderr and "health score" in p.stdout
