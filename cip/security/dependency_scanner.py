from __future__ import annotations

from pathlib import Path

from cip.security.base import Finding, ScanResult, Scanner
from cip.utils import parse_json, run_tool


class PipAuditScanner(Scanner):
    """Python dependency CVEs via pip-audit (PyPA advisory DB / OSV)."""
    name = "pip-audit"

    def _scan(self, repo: Path) -> ScanResult:
        reqs = sorted(p for p in repo.glob("requirements*.txt"))
        if reqs:
            args = []
            for r in reqs:
                args += ["-r", str(r)]
        elif (repo / "pyproject.toml").exists():
            args = [str(repo)]
        else:
            return ScanResult(self.name, "skipped", message="no requirements*.txt or pyproject.toml")
        res = run_tool("pip-audit", args + ["-f", "json", "--progress-spinner", "off", "--desc", "on"],
                       repo, timeout=1200)
        if res.skipped:
            return self._skipped(res)
        data = parse_json(res.stdout, None)
        raw = self._save_raw(res)
        if data is None:
            return ScanResult(self.name, "error", message=res.stderr[-600:], command=" ".join(res.cmd), raw_output=raw)
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        findings = []
        for dep in deps or []:
            for v in dep.get("vulns", []):
                aliases = v.get("aliases", []) or []
                cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
                fixed = ", ".join(v.get("fix_versions", []) or [])
                findings.append(Finding(
                    scanner=self.name, category="dependency",
                    # pip-audit has no severity; normalizer upgrades it from Trivy when both report it.
                    severity="MEDIUM",
                    title=f"{dep['name']} {dep.get('version', '')} – {v.get('id')}",
                    file=reqs[0].name if reqs else "pyproject.toml", rule_id=v.get("id", ""), cve=cve,
                    package=dep["name"], installed_version=dep.get("version", ""), fixed_version=fixed,
                    description=(v.get("description") or "")[:600],
                    recommendation=f"Upgrade {dep['name']} to {fixed}" if fixed else "No fixed version yet – assess exposure",
                    references=[f"https://osv.dev/vulnerability/{v.get('id')}"], confidence="HIGH",
                    also_reported_by=[a for a in aliases if a != cve],
                ))
        msg = "; ".join(f"{s.get('name')}: {s.get('skip_reason')}" for s in (data.get("dependencies", []) if isinstance(data, dict) else []) if s.get("skip_reason"))[:300]
        return ScanResult(self.name, findings=findings, command=" ".join(res.cmd), raw_output=raw, message=msg)
