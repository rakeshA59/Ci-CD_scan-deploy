"""Deterministic quality gates. The LLM never decides pass/fail."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Check:
    name: str
    actual: float | int | str
    threshold: float | int | str
    passed: bool
    comparator: str = "<="

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.name}: {self.actual} (required {self.comparator} {self.threshold})"


@dataclass
class GateResult:
    gate: str
    passed: bool
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: bool = False          # stage could not run (e.g. no Docker) – not a pass, not a fail

    def to_dict(self) -> dict:
        return {"gate": self.gate, "passed": self.passed, "skipped": self.skipped,
                "checks": [asdict(c) for c in self.checks], "notes": self.notes}


def _max(name, actual, limit) -> Check:
    return Check(name, actual, limit, actual <= limit, "<=")


def _min(name, actual, limit) -> Check:
    return Check(name, actual, limit, actual >= limit, ">=")


def security_gate(security: dict, cfg: dict) -> GateResult:
    s = security["summary"]["by_severity"]
    checks = [
        _max("critical_vulnerabilities", s["CRITICAL"], cfg.get("critical_vulnerabilities", 0)),
        _max("high_vulnerabilities", s["HIGH"], cfg.get("high_vulnerabilities", 0)),
        _max("secrets", security["summary"]["secrets"], cfg.get("secrets", 0)),
    ]
    notes = []
    skipped = [x["scanner"] for x in security["scanners"] if x["status"] in ("skipped", "error")]
    if skipped:
        notes.append(f"Scanners not run: {', '.join(skipped)}")
        if cfg.get("fail_on_skipped_scanner"):
            checks.append(Check("skipped_scanners", len(skipped), 0, False))
    return GateResult("security", all(c.passed for c in checks), checks, notes)


def test_gate(testing: dict, cfg: dict) -> GateResult:
    total = testing.get("total", 0)
    passed = testing.get("passed", 0)
    rate = round(100.0 * passed / total, 1) if total else 0.0
    cov = testing.get("coverage_percent")
    checks = [
        _min("tests_executed", total, 1),
        _min("test_pass_rate", rate, cfg.get("test_pass_rate", 100)),
        _min("coverage_percent", cov if cov is not None else 0.0, cfg.get("minimum_coverage", 80)),
    ]
    notes = []
    if testing.get("error"):
        notes.append(testing["error"])
    return GateResult("testing", all(c.passed for c in checks), checks, notes)


def container_gate(container: dict, cfg: dict) -> GateResult:
    if container.get("status") == "skipped":
        return GateResult("container", True, [], [f"Container stage skipped: {container.get('message')}"], skipped=True)
    if not container.get("image_built"):
        return GateResult("container", False, [Check("image_built", "no", "yes", False, "==")],
                          [container.get("message", "")])
    sev = container.get("scan", {}).get("by_severity", {})
    checks = [
        _max("container_critical_vulnerabilities", sev.get("CRITICAL", 0), cfg.get("container_critical_vulnerabilities", 0)),
        _max("container_high_vulnerabilities", sev.get("HIGH", 0), cfg.get("container_high_vulnerabilities", 0)),
        _max("dockerfile_high_issues", container.get("dockerfile_lint", {}).get("high", 0), cfg.get("dockerfile_high_issues", 0)),
    ]
    notes = []
    if container.get("scan", {}).get("status") in ("skipped", "error"):
        notes.append(f"Image scan not run: {str(container['scan'].get('message'))[:300]}")
        if cfg.get("require_image_scan", True):
            checks.append(Check("image_scan_completed", "no", "yes", False, "=="))
    smoke = container.get("smoke") or {}
    if smoke and smoke.get("status") != "passed":
        notes.append("Container smoke run failed – see logs in report")
        if cfg.get("require_smoke_run", True):
            checks.append(Check("container_smoke_run", smoke.get("status"), "passed", False, "=="))
    return GateResult("container", all(c.passed for c in checks), checks, notes)
