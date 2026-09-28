"""Build compact, relevant LLM context from evidence instead of dumping the whole repository."""
from __future__ import annotations

import json
from pathlib import Path

from cip.utils import read_text

ANALYSIS_CHAR_BUDGET = 60_000


def code_snippet(root: Path, file: str, line: int, radius: int = 8) -> str:
    lines = read_text(root / file).splitlines()
    if not lines:
        return ""
    start, end = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1:>5}{'>' if i + 1 == line else ' '} {lines[i]}" for i in range(start, end))


def _compact_ast(ast_info: dict) -> dict:
    files = []
    for f in ast_info["files"]:
        files.append({
            "file": f["file"],
            "imports": sorted(set(f["imports"]))[:25],
            "classes": [f"{c['name']}({', '.join(c['bases'])})" for c in f["classes"]],
            "functions": [fn["name"] for fn in f["functions"]][:30],
            "routes": [f"{r['method']} {r['path']}" for r in f["routes"]],
        })
    return {k: v for k, v in ast_info.items() if k not in ("files",)} | {"files": files}


def build_analysis_context(evidence: dict, root: Path) -> str:
    repo = evidence["repo"]
    parts = [
        "## FILE TREE\n" + repo["tree"],
        "## LANGUAGE\n" + json.dumps(evidence["language"]),
        "## DEPENDENCIES\n" + json.dumps({k: evidence["dependencies"][k] for k in
                                           ("manifests", "categories", "python_version", "unpinned", "project_meta")}),
        "## DEPENDENCY LIST\n" + ", ".join(d["name"] + d["spec"] for d in evidence["dependencies"]["dependencies"]),
    ]
    compact = _compact_ast(evidence["ast"])
    ast_json = json.dumps(compact, default=str)
    parts.append("## AST EVIDENCE\n" + ast_json[:25_000])

    # Key file excerpts: README, entry points, main app/config files.
    key = ["README.md", "Dockerfile", ".env.example", ".env_example", "docker-compose.yml"]
    key += evidence["ast"].get("entry_points", [])[:4]
    budget = ANALYSIS_CHAR_BUDGET - sum(len(p) for p in parts)
    for k in dict.fromkeys(key):
        p = root / k
        if p.exists() and budget > 1000:
            content = read_text(p, limit=min(6000, budget))
            if k.startswith(".env"):
                content = "\n".join(line.split("=")[0] + "=<redacted>" for line in content.splitlines())
            parts.append(f"## FILE: {k}\n{content}")
            budget -= len(content)
    return "\n\n".join(parts)


def build_module_context(root: Path, file_info: dict, app_summary: dict, max_chars: int = 18_000) -> str:
    src = read_text(root / file_info["file"], limit=max_chars)
    module = file_info["file"].removesuffix(".py").replace("/", ".")
    return (
        f"## APPLICATION\n{json.dumps({k: app_summary.get(k) for k in ('application_type', 'frameworks', 'databases', 'authentication')})}\n\n"
        f"## MODULE UNDER TEST\nimport path: `{module}` (file: {file_info['file']})\n"
        f"routes: {json.dumps(file_info['routes'])}\n\n```python\n{src}\n```"
    )
