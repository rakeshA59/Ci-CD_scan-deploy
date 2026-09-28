"""LLM triage of normalised findings (explain / correlate / remediate) with a rule-based fallback.

The LLM never changes severities: gate decisions stay deterministic.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from cip.llm.client import LLMClient, load_prompt
from cip.llm.context_builder import code_snippet
from cip.security.base import SECURITY_CATEGORIES, Finding

log = logging.getLogger("cip.triage")

# CWE -> (explanation, remediation) used when no LLM is available.
RULE_REMEDIATION = {
    "CWE-78": ("Possible OS command injection: shell commands built from dynamic data.",
               "Avoid shell=True / os.system; call subprocess.run([...], shell=False) with an argument list and validate inputs."),
    "CWE-89": ("Possible SQL injection: query assembled with string formatting.",
               "Use parameterised queries (cursor.execute(sql, params)) or an ORM."),
    "CWE-95": ("eval/exec on dynamic data allows arbitrary code execution.",
               "Remove eval/exec; use ast.literal_eval for literals or an explicit dispatch table."),
    "CWE-502": ("Unsafe deserialisation can lead to remote code execution.",
                "Use json or yaml.safe_load; never unpickle untrusted data."),
    "CWE-798": ("Hard-coded credential in source code.",
                "Move the secret to an environment variable / secret manager and rotate the exposed value."),
    "CWE-259": ("Hard-coded password in source code.",
                "Move the secret to an environment variable / secret manager and rotate the exposed value."),
    "CWE-327": ("Weak cryptographic algorithm.",
                "Use hashlib.sha256+ for integrity, bcrypt/argon2 for passwords (or usedforsecurity=False if non-security)."),
    "CWE-295": ("TLS certificate verification disabled – exposes traffic to MITM.",
                "Remove verify=False; configure a proper CA bundle."),
    "CWE-605": ("Service binds to all interfaces.", "Bind to a specific interface outside containers."),
    "CWE-703": ("Improper error handling (assert / bare except).", "Use explicit exceptions; don't rely on assert in production."),
    "CWE-400": ("Request without timeout can hang indefinitely.", "Pass timeout= to outbound HTTP calls."),
    "CWE-377": ("Insecure temporary file.", "Use tempfile.NamedTemporaryFile / mkstemp."),
    "CWE-330": ("Non-cryptographic randomness.", "Use the secrets module for tokens."),
}


def _rule_based(findings: list[Finding]) -> dict:
    for f in findings:
        if f.category == "code_quality":
            continue
        cwe_key = (f.cwe or "").split(":")[0].strip()
        expl, fix = RULE_REMEDIATION.get(cwe_key, (f.description, f.recommendation or "Review and remediate per scanner guidance."))
        if f.category == "dependency":
            expl = f"Known vulnerability {f.cve or f.rule_id} in {f.package} {f.installed_version}."
            fix = f.recommendation
        f.triage = {"verdict": "needs_review", "explanation": expl, "exploit_scenario": "",
                    "remediation": f.recommendation or fix, "fixed_code": "", "source": "rule-based"}
        if not f.recommendation:
            f.recommendation = fix
    sec = [f for f in findings if f.category in SECURITY_CATEGORIES]
    worst = sec[0].severity.lower() if sec else "low"
    blockers = [f"{f.id} {f.title} ({f.file}:{f.line})" for f in sec if f.severity in ("CRITICAL", "HIGH")][:10]
    return {
        "executive_summary": f"{len(sec)} security findings from deterministic scanners "
                             f"({sum(f.severity in ('CRITICAL', 'HIGH') for f in sec)} critical/high). "
                             "Rule-based triage (no LLM configured).",
        "overall_risk": worst if worst in ("critical", "high", "medium") else "low",
        "correlations": [], "top_priorities": blockers, "source": "rule-based",
    }


def triage_findings(findings: list[Finding], root: Path, llm: LLMClient, app_summary: dict,
                    max_llm: int = 25) -> dict:
    overview = _rule_based(findings)  # always populate a baseline
    if not llm.enabled:
        return overview
    targets = [f for f in findings if f.category in SECURITY_CATEGORIES][:max_llm]
    if not targets:
        return overview
    items = []
    for f in targets:
        snippet = code_snippet(root, f.file, f.line) if f.line and (root / f.file).is_file() else ""
        items.append({"id": f.id, "scanner": f.scanner, "rule": f.rule_id, "severity": f.severity,
                      "category": f.category, "title": f.title, "location": f"{f.file}:{f.line}",
                      "cwe": f.cwe, "package": f.package, "installed": f.installed_version,
                      "fixed": f.fixed_version, "description": f.description[:400], "snippet": snippet})
    user = ("## APPLICATION\n" + json.dumps({k: app_summary.get(k) for k in
            ("application_name", "purpose", "application_type", "frameworks", "authentication")}) +
            "\n\n## FINDINGS\n" + json.dumps(items, indent=1))
    try:
        result = llm.complete_json(load_prompt("security_triage"), user, max_tokens=12000)
    except Exception as e:
        log.warning("LLM triage failed (%s) – keeping rule-based triage", e)
        overview["llm_error"] = str(e)
        return overview
    by_id = {f.id: f for f in findings}
    for t in result.get("findings", []):
        f = by_id.get(t.get("id"))
        if f:
            f.triage = {**{k: t.get(k, "") for k in ("verdict", "explanation", "exploit_scenario", "remediation", "fixed_code")},
                        "source": llm.describe()}
    result.pop("findings", None)
    result["source"] = llm.describe()
    return result
