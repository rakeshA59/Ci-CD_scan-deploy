from __future__ import annotations

import json
from pathlib import Path

from cip.security.base import Finding, ScanResult, Scanner
from cip.utils import find_tool, rel, run_tool


class GitleaksScanner(Scanner):
    """Hard-coded secrets via Gitleaks (working tree, not git history, in V1)."""
    name = "gitleaks"

    def _scan(self, repo: Path) -> ScanResult:
        report_native = self.raw_dir / "gitleaks.json"
        report_native.unlink(missing_ok=True)
        # Report is written inside the repo when running via docker, then moved.
        docker_report = repo / ".cip_gitleaks.json"
        res = run_tool(
            "gitleaks",
            ["detect", "--source", "{src}", "--no-git", "--redact", "--no-banner", "--exit-code", "0",
             "--report-format", "json", "--report-path", str(report_native)],
            repo,
            docker_image="zricethezav/gitleaks:latest" if self.cfg.get("docker_fallback", True) else None,
            docker_args=["detect", "--source", "/src", "--no-git", "--redact", "--no-banner", "--exit-code", "0",
                         "--report-format", "json", "--report-path", "/src/.cip_gitleaks.json"],
        )
        if res.skipped:
            return self._skipped(res)
        if not find_tool("gitleaks") and docker_report.exists():
            report_native.write_text(docker_report.read_text(encoding="utf-8"), encoding="utf-8")
            docker_report.unlink()
        if not report_native.exists():
            return ScanResult(self.name, "error", message=(res.stderr or res.stdout)[-500:], command=" ".join(res.cmd))
        data = json.loads(report_native.read_text(encoding="utf-8") or "[]") or []
        findings = []
        for r in data:
            path = r.get("File", "")
            if path.startswith("/src/"):
                path = path[5:]
            findings.append(Finding(
                scanner=self.name, category="secret", severity="HIGH",
                title=f"Hard-coded secret: {r.get('Description') or r.get('RuleID')}",
                file=rel(path, repo) if Path(path).is_absolute() else path,
                line=int(r.get("StartLine") or 0), rule_id=r.get("RuleID", ""), cwe="CWE-798",
                description=f"Match (redacted): {r.get('Match', '')[:120]}",
                recommendation="Remove the secret from source, rotate it, and load it from an env var / secret manager.",
                confidence="HIGH",
            ))
        return ScanResult(self.name, findings=findings, command=" ".join(res.cmd), raw_output=str(report_native))
