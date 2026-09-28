from __future__ import annotations

from pathlib import Path

from cip.security.base import Finding, ScanResult, Scanner, norm_severity
from cip.utils import IGNORED_DIRS, parse_json, rel, run_tool


class BanditScanner(Scanner):
    """Python SAST via Bandit."""
    name = "bandit"

    def _scan(self, repo: Path) -> ScanResult:
        # Only exclude folders that actually exist, so the command stays readable.
        present = [d for d in sorted(IGNORED_DIRS | {"tests", "test"}) if (repo / d).is_dir()]
        excludes = ",".join(f"{{src}}/{d}" for d in present) or "{src}/.git"
        res = run_tool("bandit", ["-r", "{src}", "-f", "json", "-q", "-x", excludes], repo,
                       docker_image=None)
        if res.skipped:
            return self._skipped(res)
        data = parse_json(res.stdout, {})
        raw = self._save_raw(res)
        if not data and res.returncode not in (0, 1):
            return ScanResult(self.name, "error", message=res.stderr[-500:], command=" ".join(res.cmd), raw_output=raw)
        findings = []
        for r in data.get("results", []):
            cwe = r.get("issue_cwe", {}) or {}
            findings.append(Finding(
                scanner=self.name, category="sast", severity=norm_severity(r.get("issue_severity")),
                title=(r.get("issue_text", "").split(". ")[0][:90] if r.get("test_name") == "blacklist"
                       else r.get("test_name", r.get("test_id", "")).replace("_", " ")),
                file=rel(r.get("filename", ""), repo), line=int(r.get("line_number") or 0),
                rule_id=r.get("test_id", ""), cwe=f"CWE-{cwe['id']}" if cwe.get("id") else "",
                description=r.get("issue_text", ""), confidence=r.get("issue_confidence", ""),
                references=[r["more_info"]] if r.get("more_info") else [],
            ))
        return ScanResult(self.name, findings=findings, command=" ".join(res.cmd), raw_output=raw)
