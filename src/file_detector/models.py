from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import __version__


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Finding:
    code: str
    category: str
    severity: str
    title: str
    explanation: str
    evidence: list[str]
    points: int


@dataclass
class FileReport:
    path: str
    name: str
    size: int | None = None
    extension: str = ""
    format: str = "UNKNOWN"
    sha256: str | None = None
    status: str = "complete"
    score: int = 0
    risk: str = "indéterminé"
    score_breakdown: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    pe: dict[str, Any] | None = None


@dataclass
class ScanReport:
    target: str
    schema_version: str = "1.1"
    engine_version: str = __version__
    started_at: str = field(default_factory=timestamp)
    finished_at: str | None = None
    files: list[FileReport] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    truncated: bool = False
    cancelled: bool = False
    excluded_entries: int = 0
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["summary"] = {
            "total": len(self.files),
            "with_findings": sum(bool(f.findings) for f in self.files),
            "incomplete": sum(f.status != "complete" for f in self.files),
            "high_risk": sum(f.risk == "élevé" for f in self.files),
        }
        return result
