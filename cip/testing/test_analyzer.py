"""Decide which modules need generated tests and what scenarios they should cover."""
from __future__ import annotations

from pathlib import Path


def _is_test_file(path: str) -> bool:
    p = Path(path)
    return p.name.startswith("test_") or p.name.endswith("_test.py") or "tests" in p.parts or p.name == "conftest.py"


def _tested_modules(ast_info: dict) -> set[str]:
    """Modules imported by existing tests (rough 'already has tests' signal)."""
    tested = set()
    for f in ast_info["files"]:
        if _is_test_file(f["file"]):
            for imp in f["imports"]:
                tested.add(imp.lstrip("."))
    return tested


def select_modules(ast_info: dict, max_modules: int) -> list[dict]:
    tested = _tested_modules(ast_info)
    candidates = []
    for f in ast_info["files"]:
        path = f["file"]
        if _is_test_file(path) or f["syntax_error"] or Path(path).name in ("setup.py", "manage.py"):
            continue
        if "migrations" in path or path.startswith(("docs/", "scripts/")):
            continue
        public_fns = [fn for fn in f["functions"] if not fn["private"]]
        methods = [m for c in f["classes"] for m in c["methods"] if not m["private"]]
        testable = len(public_fns) + len(methods) + 2 * len(f["routes"])
        kind = "streamlit" if any(a["type"] == "Streamlit" for a in f["app_objects"]) else \
            "script" if f.get("is_script") else "module"
        if testable == 0 and kind == "module":
            continue
        if kind != "module":
            testable = max(testable, 3)   # a whole app/script with no functions still deserves a test
        module = path.removesuffix(".py").replace("/", ".")
        already = module in tested or any(t.endswith("." + module.split(".")[-1]) for t in tested)
        score = testable + sum(fn["complexity"] for fn in public_fns + methods) / 5 + (0 if already else 5)
        scenarios = []
        for fn in public_fns + methods:
            label = f"{fn['class'] + '.' if fn['class'] else ''}{fn['name']}"
            s = ["happy path"]
            if fn["raises"]:
                s.append("raises " + ", ".join(fn["raises"]))
            if fn["complexity"] > 3:
                s.append(f"branches (complexity {fn['complexity']})")
            if fn["args"]:
                s.append("edge/invalid inputs")
            scenarios.append({"target": label, "scenarios": s})
        for r in f["routes"]:
            scenarios.append({"target": f"{r['method']} {r['path']}",
                              "scenarios": ["success response", "validation error (422)"] +
                                           (["unauthorised access"] if r.get("auth_dependency") else [])})
        if kind == "streamlit":
            scenarios.insert(0, {"target": path, "scenarios": [
                "Streamlit app renders without exceptions (streamlit.testing.v1.AppTest)",
                "behaviour when required env vars / API keys are missing",
                "main widgets present (title, inputs, buttons); LLM/HTTP calls mocked"]})
        elif kind == "script":
            scenarios.insert(0, {"target": path, "scenarios": ["script compiles", "script runs with external calls mocked"]})
        candidates.append({"file": path, "module": module, "score": round(score, 1), "kind": kind,
                           "has_existing_tests": already, "info": f, "scenarios": scenarios})
    candidates.sort(key=lambda c: -c["score"])
    return candidates[:max_modules]
