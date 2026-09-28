"""Merge scanner outputs into one de-duplicated, sorted, summarised finding list."""
from __future__ import annotations

from collections import Counter

from cip.security.base import SECURITY_CATEGORIES, SEVERITIES, SEVERITY_RANK, Finding, ScanResult


def _key(f: Finding) -> tuple:
    if f.category == "dependency":
        return ("dep", f.package.lower().replace("_", "-"), f.cve or f.rule_id)
    if f.category in ("sast", "secret"):
        # Bandit + Semgrep often flag the same line for the same weakness.
        return ("code", f.file, f.line, f.cwe or f.rule_id)
    return (f.scanner, f.file, f.line, f.rule_id)


def normalize(results: list[ScanResult]) -> dict:
    merged: dict[tuple, Finding] = {}
    for res in results:
        for f in res.findings:
            k = _key(f)
            if k in merged:
                existing = merged[k]
                if f.scanner not in existing.also_reported_by and f.scanner != existing.scanner:
                    existing.also_reported_by.append(f.scanner)
                # keep the most severe rating and richest data
                if SEVERITY_RANK[f.severity] < SEVERITY_RANK[existing.severity]:
                    existing.severity = f.severity
                existing.fixed_version = existing.fixed_version or f.fixed_version
                existing.recommendation = existing.recommendation or f.recommendation
            else:
                merged[k] = f

    findings = sorted(merged.values(), key=lambda f: (SEVERITY_RANK[f.severity],
                                                       f.category == "code_quality", f.file, f.line))
    for i, f in enumerate(findings, 1):
        f.id = f"F{i:03d}"

    sec = [f for f in findings if f.category in SECURITY_CATEGORIES]
    by_sev = Counter(f.severity for f in sec)
    by_cat = Counter(f.category for f in findings)
    return {
        "findings": findings,
        "summary": {
            "total": len(findings),
            "security_total": len(sec),
            "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
            "by_category": dict(by_cat),
            "by_scanner": dict(Counter(f.scanner for f in findings)),
            "secrets": by_cat.get("secret", 0),
            "dependency_vulns": by_cat.get("dependency", 0),
            "sast": by_cat.get("sast", 0),
            "misconfigurations": by_cat.get("misconfiguration", 0),
            "code_quality": by_cat.get("code_quality", 0),
        },
        "scanners": [r.summary() for r in results],
    }
