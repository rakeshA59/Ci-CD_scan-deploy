from __future__ import annotations

from pathlib import Path

from cip.security.base import Finding, ScanResult, Scanner
from cip.utils import parse_json, rel, run_tool

# Ruff rules that indicate real bugs rather than style -> MEDIUM, everything else LOW.
BUG_RULES = ("F821", "F822", "F823", "E9", "F63", "F7", "B006", "B008", "B904", "B017", "F811")


class RuffScanner(Scanner):
    """Code quality / lint via Ruff (non-blocking category `code_quality`)."""
    name = "ruff"

    def _scan(self, repo: Path) -> ScanResult:
        res = run_tool("ruff", ["check", "{src}", "--output-format", "json", "--exit-zero", "--no-cache",
                                "--select", "E,F,W,B,C90,UP,SIM", "--ignore", "E501,W291,W293,UP",
                                "--extend-exclude", ".venv,venv,.cip"], repo)
        if res.skipped:
            return self._skipped(res)
        data = parse_json(res.stdout, None)
        raw = self._save_raw(res)
        if data is None:
            return ScanResult(self.name, "error", message=res.stderr[-500:], command=" ".join(res.cmd), raw_output=raw)
        findings = []
        for r in data:
            code = r.get("code") or "E999"
            findings.append(Finding(
                scanner=self.name, category="code_quality",
                severity="MEDIUM" if code.startswith(BUG_RULES) else "LOW",
                title=f"{code}: {r.get('message', '')[:90]}",
                file=rel(r.get("filename", ""), repo), line=int((r.get("location") or {}).get("row") or 0),
                rule_id=code, description=r.get("message", ""),
                recommendation=((r.get("fix") or {}).get("message") or "") if r.get("fix") else "",
                references=[r["url"]] if r.get("url") else [],
            ))
        return ScanResult(self.name, findings=findings, command=" ".join(res.cmd), raw_output=raw)
