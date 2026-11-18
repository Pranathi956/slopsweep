"""Core data models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


# Categories
SECURITY = "security"
SLOP = "slop"
GAP = "coding-gap"
LOOSE_END = "loose-end"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    snippet: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.name] += 1
        return out

    def counts_by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def score(self) -> int:
        """Health score 0-100 (100 = clean). Weighted by severity."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 10,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - penalty)
