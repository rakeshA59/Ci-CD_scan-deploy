"""Trivy image scan of the built container."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from cip.security.base import SEVERITIES, Finding
from cip.security.trivy_scanner import parse_trivy, run_trivy, trivy_error
from cip.utils import parse_json


def scan_image(image: str, raw_file: Path, repo: Path) -> dict:
    res = run_trivy(["image", "--scanners", "vuln,secret", "--format", "json", "--quiet", image], repo, timeout=2400)
    if res.skipped:
        return {"status": "skipped", "message": res.skip_reason, "by_severity": {}, "findings": []}
    data = parse_json(res.stdout, None)
    raw_file.write_text(res.stdout or res.stderr, encoding="utf-8")
    if data is None:
        return {"status": "error", "message": trivy_error(res.stderr), "by_severity": {}, "findings": []}
    findings = parse_trivy(data, "trivy-image", "container")
    for r in data.get("Results", []) or []:
        for s in r.get("Secrets", []) or []:
            findings.append(Finding(scanner="trivy-image", category="secret", severity="HIGH",
                                    title=f"Secret in image: {s.get('Title')}", file=r.get("Target", ""),
                                    line=int(s.get("StartLine") or 0), rule_id=s.get("RuleID", "")))
    sev = Counter(f.severity for f in findings)
    os_info = (data.get("Metadata") or {}).get("OS") or {}
    return {"status": "ok", "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "total": len(findings), "os": f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip(),
            "fixable": sum(1 for f in findings if f.fixed_version),
            "findings": [f.to_dict() for f in findings]}
