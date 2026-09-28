from __future__ import annotations

from pathlib import Path

from cip.config import PROJECT_ROOT
from cip.security.base import Finding, ScanResult, Scanner, norm_severity
from cip.utils import parse_json, rel, run_tool

LOCAL_RULES = PROJECT_ROOT / "config" / "semgrep_rules.yml"


class SemgrepScanner(Scanner):
    """SAST patterns via Semgrep. Uses registry rulesets (needs internet) plus bundled local rules."""
    name = "semgrep"

    def _scan(self, repo: Path) -> ScanResult:
        configs = list(self.cfg.get("semgrep_configs") or [])
        args = ["scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for c in configs:
            args += ["--config", c]
        native_args = list(args)
        if LOCAL_RULES.exists():
            native_args += ["--config", str(LOCAL_RULES)]
        res = run_tool("semgrep", native_args + ["{src}"], repo,
                       docker_image="semgrep/semgrep" if self.cfg.get("docker_fallback", True) else None,
                       docker_args=args + ["/src"], timeout=1200)
        if res.skipped:
            return self._skipped(res)
        data = parse_json(res.stdout, {})
        # Registry unreachable (offline / proxy) -> retry with local rules only.
        if (not data or not data.get("results") and data.get("errors")) and configs and LOCAL_RULES.exists():
            res2 = run_tool("semgrep", ["scan", "--json", "--quiet", "--metrics=off", "--config", str(LOCAL_RULES), "{src}"], repo)
            d2 = parse_json(res2.stdout, {})
            if d2:
                res, data = res2, d2
        raw = self._save_raw(res)
        if not data:
            return ScanResult(self.name, "error", message=(res.stderr or res.stdout)[-500:], command=" ".join(res.cmd), raw_output=raw)
        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            cwe = meta.get("cwe")
            cwe = cwe[0] if isinstance(cwe, list) and cwe else (cwe or "")
            path = r.get("path", "")
            if path.startswith("/src/"):
                path = path[5:]
            is_secret = "secret" in r.get("check_id", "").lower()
            findings.append(Finding(
                scanner=self.name, category="secret" if is_secret else "sast",
                severity=norm_severity(meta.get("impact") if meta.get("impact") in ("HIGH", "CRITICAL") else extra.get("severity")),
                title=r.get("check_id", "").split(".")[-1].replace("-", " "),
                file=rel(path, repo) if Path(path).is_absolute() else path,
                line=int(r.get("start", {}).get("line") or 0), rule_id=r.get("check_id", ""),
                cwe=str(cwe).split(":")[0], description=extra.get("message", ""),
                confidence=meta.get("confidence", ""), references=(meta.get("references") or [])[:3],
            ))
        errs = [e.get("message", "")[:200] for e in data.get("errors", [])][:3]
        return ScanResult(self.name, findings=findings, command=" ".join(res.cmd), raw_output=raw,
                          message="; ".join(errs))
