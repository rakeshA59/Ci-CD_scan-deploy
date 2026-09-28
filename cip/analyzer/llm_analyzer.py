"""Phase 1b – turn deterministic evidence into an application understanding.

The LLM interprets evidence; when no LLM is configured a heuristic summary is produced
from the same evidence so the pipeline still yields a useful report.
"""
from __future__ import annotations

import logging
from pathlib import Path

from cip.llm.client import LLMClient, load_prompt
from cip.llm.context_builder import build_analysis_context

log = logging.getLogger("cip.analyzer")


def heuristic_summary(evidence: dict) -> dict:
    deps = evidence["dependencies"]
    ast_info = evidence["ast"]
    cats = deps.get("categories", {})
    techs = set(ast_info.get("technologies_from_imports", []))
    frameworks = cats.get("framework", []) or [t for t in techs if t in ("FastAPI", "Flask", "Django", "Streamlit")]
    dbs = cats.get("database", []) + cats.get("vector_db", []) or [t for t in techs if t in ("MongoDB", "SQLAlchemy", "Redis", "PostgreSQL", "ChromaDB")]
    auth = cats.get("auth", []) or (["JWT"] if "JWT" in techs else [])
    routes = ast_info.get("routes", [])
    unauth = [r for r in routes if not r.get("auth_dependency")]

    if routes:
        app_type = "REST API backend"
    elif any(f in frameworks for f in ("Streamlit", "Gradio")):
        app_type = "Interactive web app"
    elif ast_info.get("entry_points"):
        app_type = "Python application / CLI"
    else:
        app_type = "Python library"

    obs = []
    if routes and unauth:
        obs.append(f"{len(unauth)} of {len(routes)} routes have no detectable auth dependency")
    if ast_info.get("dangerous_calls"):
        obs.append(f"{len(ast_info['dangerous_calls'])} potentially dangerous call sites (eval/subprocess/pickle ...)")
    if deps.get("unpinned"):
        obs.append(f"{len(deps['unpinned'])} dependencies are not pinned to exact versions")

    return {
        "application_name": deps.get("project_meta", {}).get("project_name") or evidence["repo"]["name"],
        "purpose": "Heuristic analysis (no LLM configured): purpose inferred from structure only. "
                   f"{app_type} built with {', '.join(frameworks) or 'plain Python'}"
                   f"{' using ' + ', '.join(dbs) if dbs else ''}.",
        "application_type": app_type,
        "language": f"Python {deps.get('python_version') or '3.x'}",
        "frameworks": frameworks,
        "databases": dbs,
        "authentication": ", ".join(auth) or "none detected",
        "external_integrations": cats.get("ai", []) + cats.get("cloud", []) + cats.get("messaging", []),
        "architecture_style": "Layered (" + " / ".join(d for d in evidence["repo"]["top_level_dirs"][:8]) + ")"
        if evidence["repo"]["top_level_dirs"] else "Flat module layout",
        "components": [{"name": d, "path": d + "/", "responsibility": "unknown (heuristic)"}
                       for d in evidence["repo"]["top_level_dirs"][:10]],
        "entry_points": ast_info.get("entry_points", []),
        "api_surface": f"{len(routes)} HTTP routes detected" if routes else "No HTTP routes detected",
        "configuration": f"Environment variables: {', '.join(ast_info.get('env_vars', [])[:15]) or 'none detected'}",
        "testing": f"{len(evidence['repo']['test_files'])} test files" if evidence["repo"]["has_tests"] else "none",
        "deployment": "Dockerfile present" if evidence["repo"]["has_dockerfile"] else "none detected",
        "security_observations": obs,
        "risks_and_gaps": [] if evidence["repo"]["has_tests"] else ["No automated tests found"],
        "confidence": "low",
        "generated_by": "heuristic",
    }


def analyze_application(evidence: dict, root: Path, llm: LLMClient) -> dict:
    if not llm.enabled:
        return heuristic_summary(evidence)
    try:
        context = build_analysis_context(evidence, root)
        result = llm.complete_json(load_prompt("app_analysis"), context, max_tokens=4000)
        result["generated_by"] = llm.describe()
        return result
    except Exception as e:
        log.warning("LLM application analysis failed (%s) – using heuristic summary", e)
        out = heuristic_summary(evidence)
        out["llm_error"] = str(e)
        return out
