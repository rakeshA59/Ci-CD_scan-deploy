"""Common finding schema shared by every scanner (the "unified report" format)."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from cip.utils import CmdResult

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Categories counted as *security* (gate-relevant). code_quality is reported but non-blocking.
SECURITY_CATEGORIES = {"sast", "dependency", "secret", "misconfiguration", "container"}


def norm_severity(value: str | None, default: str = "MEDIUM") -> str:
    v = (value or "").upper()
    mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "NOTE": "LOW", "INFO": "INFO",
               "UNKNOWN": default, "MODERATE": "MEDIUM", "INFORMATIONAL": "INFO"}
    v = mapping.get(v, v)
    return v if v in SEVERITY_RANK else default


@dataclass
class Finding:
    scanner: str
    category: str                 # sast | dependency | secret | code_quality | misconfiguration | container
    severity: str
    title: str
    file: str = ""
    line: int = 0
    rule_id: str = ""
    cwe: str = ""
    cve: str = ""
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    description: str = ""
    recommendation: str = ""
    confidence: str = ""
    references: list[str] = field(default_factory=list)
    also_reported_by: list[str] = field(default_factory=list)
    id: str = ""
    # filled by LLM / rule-based triage
    triage: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    scanner: str
    status: str = "passed"        # passed | findings | skipped | error
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    message: str = ""
    command: str = ""
    raw_output: Optional[str] = None

    def summary(self) -> dict:
        return {"scanner": self.scanner, "status": self.status, "findings": len(self.findings),
                "duration_s": round(self.duration_s, 1), "message": self.message, "command": self.command,
                "raw_output": self.raw_output}


class Scanner:
    name = "base"

    def __init__(self, cfg: dict, raw_dir: Path):
        self.cfg = cfg
        self.raw_dir = raw_dir
        raw_dir.mkdir(parents=True, exist_ok=True)

    def scan(self, repo: Path) -> ScanResult:
        t0 = time.time()
        try:
            result = self._scan(repo)
        except Exception as e:  # a broken scanner must never crash the pipeline
            result = ScanResult(self.name, status="error", message=f"{type(e).__name__}: {e}")
        result.duration_s = time.time() - t0
        if result.status == "passed" and result.findings:
            result.status = "findings"
        return result

    def _scan(self, repo: Path) -> ScanResult:  # pragma: no cover
        raise NotImplementedError

    # helpers
    def _save_raw(self, res: CmdResult, suffix: str = "json") -> str:
        path = self.raw_dir / f"{self.name}.{suffix}"
        path.write_text(res.stdout or res.stderr or "", encoding="utf-8")
        return str(path)

    def _skipped(self, res: CmdResult) -> ScanResult:
        return ScanResult(self.name, status="skipped", message=res.skip_reason, command=" ".join(res.cmd))
