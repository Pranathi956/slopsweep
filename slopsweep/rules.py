"""Language-agnostic regex rules (work on any text file)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import GAP, LOOSE_END, SECURITY, SLOP, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    message: str
    fix: str = ""
    # restrict to file extensions (None = all text files)
    exts: frozenset[str] | None = None
    # lines matching this are ignored (e.g. placeholders)
    ignore: re.Pattern | None = None


def _r(id_, cat, sev, pat, msg, fix="", exts=None, ignore=None, flags=0):
    return Rule(
        id_, cat, sev, re.compile(pat, flags), msg, fix,
        frozenset(exts) if exts else None,
        re.compile(ignore, re.I) if ignore else None,
    )


CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
             ".rs", ".c", ".cpp", ".cs", ".kt", ".swift", ".sh", ".mjs", ".cjs"}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

PLACEHOLDER = r"(example|your[_-]?|changeme|placeholder|xxxx|<.+>|\$\{|%\(|os\.environ|getenv|process\.env|dummy|sample|test)"

RULES: list[Rule] = [
    # ---------------- SECURITY: secrets ----------------
    _r("SEC001", SECURITY, Severity.CRITICAL, r"AKIA[0-9A-Z]{16}",
       "AWS access key ID committed", "Rotate the key and load it from env/secret manager."),
    _r("SEC002", SECURITY, Severity.CRITICAL, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
       "Private key committed to repo", "Remove, rotate the key, add to .gitignore."),
    _r("SEC003", SECURITY, Severity.CRITICAL, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
       "GitHub token committed", "Revoke the token and use a secret store."),
    _r("SEC004", SECURITY, Severity.CRITICAL, r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
       "Slack token committed", "Revoke the token and use a secret store."),
    _r("SEC005", SECURITY, Severity.CRITICAL, r"\bsk-[A-Za-z0-9_-]{32,}\b",
       "Possible LLM/API secret key (sk-...) committed", "Revoke and load from environment."),
    _r("SEC006", SECURITY, Severity.CRITICAL, r"AIza[0-9A-Za-z_-]{35}",
       "Google API key committed", "Restrict/rotate the key; load from environment."),
    _r("SEC007", SECURITY, Severity.HIGH,
       r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*(['"])(?!\s*\1)[^'"\s]{6,}\1""",
       "Hardcoded credential-like literal", "Read it from an environment variable or secret manager.",
       ignore=PLACEHOLDER),
    _r("SEC008", SECURITY, Severity.HIGH,
       r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]+@",
       "Connection string with embedded credentials", "Move credentials to environment config.",
       ignore=PLACEHOLDER),
    _r("SEC009", SECURITY, Severity.HIGH, r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{30,}",
       "Hardcoded bearer token", "Never hardcode tokens; inject at runtime.", ignore=PLACEHOLDER),

    # ---------------- SECURITY: dangerous code ----------------
    _r("SEC020", SECURITY, Severity.HIGH, r"\beval\s*\(",
       "eval() executes arbitrary code", "Use a safe parser (json.loads / ast.literal_eval).",
       exts=JS_EXTS | {".php", ".rb"}),
    _r("SEC021", SECURITY, Severity.MEDIUM, r"\b(?:innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML|document\.write\s*\(",
       "Raw HTML injection sink (XSS risk)", "Use textContent or sanitize with DOMPurify.", exts=JS_EXTS),
    _r("SEC022", SECURITY, Severity.HIGH, r"(?i)\b(?:execute|query|exec)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+)|`[^`]*\$\{)",
       "SQL built via string formatting/concatenation (injection risk)",
       "Use parameterized queries.", exts=CODE_EXTS),
    _r("SEC023", SECURITY, Severity.MEDIUM, r"(?i)verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
       "TLS certificate verification disabled", "Keep verification on; pin a CA bundle if needed."),
    _r("SEC024", SECURITY, Severity.MEDIUM, r"(?i)\b(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\b|createHash\(\s*['\"](?:md5|sha1)['\"]",
       "Weak hash (MD5/SHA1)", "Use SHA-256+, and bcrypt/argon2 for passwords.", exts=CODE_EXTS),
    _r("SEC025", SECURITY, Severity.MEDIUM, r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]",
       "Wildcard CORS policy", "Restrict to known origins.", exts=CODE_EXTS),
    _r("SEC026", SECURITY, Severity.MEDIUM, r"(?i)\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True",
       "Debug mode enabled", "Drive debug from env and keep it off in production.", exts={".py"}),
    _r("SEC027", SECURITY, Severity.MEDIUM, r"(?i)\bhost\s*=\s*['\"]0\.0\.0\.0['\"]",
       "Binding to all interfaces", "Bind to 127.0.0.1 unless exposure is intended.", exts={".py"}),
    _r("SEC028", SECURITY, Severity.HIGH, r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe))",
       "Unsafe deserialization", "Use json or yaml.safe_load.", exts={".py"}),
    _r("SEC029", SECURITY, Severity.MEDIUM, r"(?i)\bchmod\s+(?:-R\s+)?7[0-7]{2}\b|os\.chmod\([^,]+,\s*0o?777",
       "World-writable permissions", "Use least-privilege permissions (e.g. 640/750)."),
    _r("SEC030", SECURITY, Severity.LOW, r"\brandom\.(?:random|randint|choice)\s*\(.*(?:token|secret|password|key)",
       "Non-cryptographic RNG used for a secret", "Use the `secrets` module.", exts={".py"}),
    _r("SEC031", SECURITY, Severity.MEDIUM, r"(?i)curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
       "Piping remote script into a shell", "Download, verify checksum, then execute."),

    # ---------------- SLOP: AI-generated / low-effort leftovers ----------------
    _r("SLP001", SLOP, Severity.MEDIUM,
       r"(?i)(?:#|//|/\*|\*|--)\s*(?:as an ai\b|as a language model|i(?:'ve| have) (?:updated|implemented|fixed|added)|here(?:'s| is) (?:the|an?|your) (?:updated|implementation|code|fixed)|certainly!|sure!|let me know if you)",
       "Leftover AI-assistant chatter in a comment", "Delete conversational filler."),
    _r("SLP002", SLOP, Severity.LOW,
       r"(?i)(?:#|//)\s*(?:this (?:function|method|class) (?:is used to|will|does the following)|(?:initialize|initialise|increment|import|return|define|create|set|get|loop through|call)s? (?:the |a |an )?\w+\s*$)",
       "Obvious comment restating the code", "Remove or replace with a comment explaining *why*."),
    _r("SLP003", SLOP, Severity.MEDIUM, r"(?i)\b(?:lorem ipsum|foo\s*bar baz|asdf+|qwerty|test123)\b",
       "Placeholder/filler text left in code", "Replace with real content or remove."),
    _r("SLP004", SLOP, Severity.MEDIUM,
       r"(?i)(?:#|//|/\*)\s*(?:\.\.\.\s*)?(?:rest of (?:the )?(?:code|file|implementation)|(?:your|add) (?:code|logic|implementation) here|implementation (?:goes )?here|existing code (?:here|remains)|same as before)",
       "Truncated-generation placeholder comment", "Implement the missing code."),
    _r("SLP005", SLOP, Severity.LOW, r"\bconsole\.(?:log|debug)\s*\(|\bdebugger\s*;?\s*$",
       "Debug output left in code", "Remove or use a real logger.", exts=JS_EXTS),
    _r("SLP006", SLOP, Severity.LOW, r"^\s*print\s*\(\s*['\"](?:here|debug|test|hello|xxx|got here|reached)[^'\"]*['\"]\s*\)",
       "Debug print left in code", "Remove or use logging.", exts={".py"}),
    _r("SLP007", SLOP, Severity.LOW, r"^\s*(?:#|//)\s*(?:[A-Za-z_][\w\.]*\s*(?:=|\()[^\n]*|(?:if|for|while|return|def|class|import|from)\b[^\n]*[:;{)]\s*)$",
       "Commented-out code", "Delete it — version control remembers.", exts=CODE_EXTS),
    _r("SLP008", SLOP, Severity.LOW, r"(?i)\b(?:foo|bar|baz|temp\d*|tmp\d*|data\d+|result\d+|var\d+|thing|stuff)\s*=\s*",
       "Low-signal variable name", "Use a descriptive name.", exts=CODE_EXTS),

    # ---------------- LOOSE ENDS ----------------
    _r("LOS001", LOOSE_END, Severity.LOW, r"\b(TODO|FIXME|HACK|XXX|BUG|TBD)\b[:\s(]",
       "Unresolved marker comment", "Resolve it or open a tracked issue."),
    _r("LOS002", LOOSE_END, Severity.MEDIUM, r"(?i)\bnot\s*implemented(?:error)?\b|raise\s+NotImplementedError|unimplemented!\s*\(|todo!\s*\(",
       "Unimplemented stub", "Implement or remove the stub.", exts=CODE_EXTS),
    _r("LOS003", LOOSE_END, Severity.LOW, r"(?i)\b(?:https?://)?(?:localhost|127\.0\.0\.1):\d{2,5}",
       "Hardcoded localhost URL", "Make the endpoint configurable.", exts=CODE_EXTS),
    _r("LOS004", LOOSE_END, Severity.LOW, r"(?i)\b(?:temporary|temp|quick)\s+(?:fix|hack|workaround)\b|\bworkaround\b|for now\b",
       "Temporary workaround noted in code", "Make it permanent or track it.", exts=CODE_EXTS),
    _r("LOS005", LOOSE_END, Severity.MEDIUM, r"(?i)(?:#|//)\s*(?:noqa|nosec|type:\s*ignore|eslint-disable|@ts-ignore|@ts-nocheck|pylint:\s*disable)",
       "Linter/type-checker suppression", "Fix the underlying issue or justify the suppression.", exts=CODE_EXTS),

    # ---------------- CODING GAPS (regex-based) ----------------
    _r("GAP001", GAP, Severity.MEDIUM, r"\bcatch\s*\([^)]*\)\s*\{\s*\}|\.catch\s*\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)",
       "Empty catch block swallows errors", "Handle or log the error.", exts=JS_EXTS | {".java", ".cs", ".php"}),
    _r("GAP002", GAP, Severity.LOW, r"(?i)\bsetTimeout\s*\([^,]+,\s*\d{5,}\)",
       "Very long hardcoded timeout", "Make it configurable.", exts=JS_EXTS),
    _r("GAP003", GAP, Severity.MEDIUM, r"\b(?:requests|httpx)\.(?:get|post|put|delete|patch|head)\s*\((?![^)]*timeout)[^)]*\)",
       "HTTP call without timeout (can hang forever)", "Pass timeout=<seconds>.", exts={".py"}),
]

# Files that are intentionally allowed to have example secrets etc.
SECRET_RULE_PREFIX = "SEC0"
