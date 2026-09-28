"""Deterministic Python source analysis using the `ast` module.

Extracts imports, functions, classes, decorators, HTTP routes, entry points, env-var usage
and potentially dangerous calls – the evidence the LLM later interprets.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from cip.utils import iter_files, read_text, rel

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "route", "api_route", "websocket"}

DANGEROUS_CALLS = {
    "eval": "Dynamic code execution", "exec": "Dynamic code execution",
    "compile": "Dynamic code compilation", "os.system": "Shell command execution",
    "os.popen": "Shell command execution", "subprocess.call": "Subprocess execution",
    "subprocess.run": "Subprocess execution", "subprocess.Popen": "Subprocess execution",
    "subprocess.check_output": "Subprocess execution", "pickle.load": "Unsafe deserialisation",
    "pickle.loads": "Unsafe deserialisation", "yaml.load": "Unsafe YAML load",
    "marshal.loads": "Unsafe deserialisation", "input": "Raw user input",
    "tempfile.mktemp": "Insecure temp file", "hashlib.md5": "Weak hash", "hashlib.sha1": "Weak hash",
    "random.random": "Non-crypto randomness", "requests.get": "Outbound HTTP", "requests.post": "Outbound HTTP",
}

IMPORT_TECH = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django", "pymongo": "MongoDB", "motor": "MongoDB",
    "sqlalchemy": "SQLAlchemy", "jwt": "JWT", "jose": "JWT", "langchain": "LangChain",
    "langgraph": "LangGraph", "openai": "OpenAI", "anthropic": "Anthropic", "pydantic": "Pydantic",
    "redis": "Redis", "celery": "Celery", "boto3": "AWS", "chromadb": "ChromaDB", "pytest": "pytest",
    "streamlit": "Streamlit", "requests": "requests", "httpx": "httpx", "psycopg2": "PostgreSQL",
}


def _name(node: ast.AST) -> str:
    """Dotted name for Name/Attribute/Call chains, e.g. `subprocess.run`, `app.get`."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _complexity(fn: ast.AST) -> int:
    branches = (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.BoolOp, ast.IfExp,
                ast.ExceptHandler, ast.comprehension, ast.AsyncFor, ast.AsyncWith, ast.Match)
    return 1 + sum(isinstance(n, branches) for n in ast.walk(fn))


def _const(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def analyze_file(path: Path, root: Path) -> dict:
    src = read_text(path)
    info: dict = {"file": rel(path, root), "loc": src.count("\n") + 1, "imports": [], "functions": [],
                  "classes": [], "routes": [], "dangerous_calls": [], "env_vars": [], "entry_point": False,
                  "app_objects": [], "syntax_error": None}
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        info["syntax_error"] = f"line {e.lineno}: {e.msg}"
        return info

    router_prefixes: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            info["imports"] += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            info["imports"].append(("." * node.level) + node.module)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            ctor = _name(node.value.func).split(".")[-1]
            if ctor in ("FastAPI", "Flask", "APIRouter", "Blueprint", "Celery"):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        info["app_objects"].append({"name": t.id, "type": ctor, "line": node.lineno})
                        for kw in node.value.keywords:
                            if kw.arg == "prefix" and _const(kw.value):
                                router_prefixes[t.id] = _const(kw.value)
        elif isinstance(node, ast.Call):
            cname = _name(node.func)
            if cname in DANGEROUS_CALLS or cname.split(".")[-1] in ("eval", "exec"):
                entry = {"call": cname, "line": node.lineno, "risk": DANGEROUS_CALLS.get(cname, "Dynamic code execution")}
                if cname.startswith("subprocess") and any(k.arg == "shell" and getattr(k.value, "value", False) is True for k in node.keywords):
                    entry["risk"] += " (shell=True)"
                if cname == "yaml.load" and any(k.arg == "Loader" and "Safe" in _name(k.value) for k in node.keywords):
                    continue
                info["dangerous_calls"].append(entry)
            if cname in ("os.getenv", "os.environ.get", "getenv") and node.args and _const(node.args[0]):
                info["env_vars"].append(_const(node.args[0]))
            if cname in ("uvicorn.run", "app.run", "main"):
                info["entry_point"] = True
        elif isinstance(node, ast.Subscript) and _name(node.value) == "os.environ" and _const(node.slice):
            info["env_vars"].append(_const(node.slice))
        elif isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare) and _name(test.left) == "__name__"
                    and any(_const(c) == "__main__" for c in test.comparators)):
                info["entry_point"] = True

    def fn_record(fn, cls: str | None = None) -> dict:
        args = [a.arg for a in fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls")]
        decos = [_name(d) for d in fn.decorator_list]
        rec = {
            "name": fn.name, "class": cls, "line": fn.lineno, "async": isinstance(fn, ast.AsyncFunctionDef),
            "args": args, "decorators": decos, "docstring": bool(ast.get_docstring(fn)),
            "complexity": _complexity(fn), "returns": ast.unparse(fn.returns) if fn.returns else None,
            "raises": sorted({_name(n.exc) for n in ast.walk(fn) if isinstance(n, ast.Raise) and n.exc}),
            "private": fn.name.startswith("_"),
        }
        for d in fn.decorator_list:
            dname = _name(d)
            parts = dname.split(".")
            if len(parts) == 2 and parts[1] in HTTP_METHODS and isinstance(d, ast.Call):
                path_arg = _const(d.args[0]) if d.args else next((_const(k.value) for k in d.keywords if k.arg == "path"), "")
                methods = [parts[1].upper()]
                if parts[1] in ("route", "api_route"):
                    for k in d.keywords:
                        if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple)):
                            methods = [_const(e) or "?" for e in k.value.elts]
                    if parts[1] == "route" and methods == ["ROUTE"]:
                        methods = ["GET"]
                info["routes"].append({
                    "method": ",".join(methods), "path": router_prefixes.get(parts[0], "") + (path_arg or ""),
                    "handler": fn.name, "line": fn.lineno, "object": parts[0],
                    "auth_dependency": "Depends" in ast.unparse(fn.args) and any(
                        w in ast.unparse(fn.args).lower() for w in ("user", "auth", "token", "verify")),
                })
        return rec

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info["functions"].append(fn_record(node))
        elif isinstance(node, ast.ClassDef):
            methods = [fn_record(n, node.name) for n in node.body
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            info["classes"].append({"name": node.name, "line": node.lineno,
                                    "bases": [_name(b) for b in node.bases], "methods": methods,
                                    "docstring": bool(ast.get_docstring(node))})
    info["env_vars"] = sorted(set(info["env_vars"]))
    # Script-style modules: real work at module level, not inside functions (e.g. a Streamlit app).
    top_level_calls = sum(1 for n in tree.body if isinstance(n, (ast.Expr, ast.If, ast.With, ast.For, ast.Assign))
                          and any(isinstance(x, ast.Call) for x in ast.walk(n)))
    info["is_script"] = top_level_calls >= 3 and not info["functions"] and not info["classes"]
    imports_streamlit = any(i == "streamlit" or i.startswith("streamlit.") for i in info["imports"])
    if imports_streamlit and top_level_calls:
        info["app_objects"].append({"name": "streamlit", "type": "Streamlit", "line": 1})
        info["entry_point"] = True
    return info


def analyze_ast(root: Path) -> dict:
    files = []
    for p in iter_files(root, {".py"}):
        files.append(analyze_file(p, root))

    import_roots = Counter()
    for f in files:
        for imp in f["imports"]:
            if not imp.startswith("."):
                import_roots[imp.split(".")[0]] += 1

    local_modules = {Path(f["file"]).parts[0].removesuffix(".py") for f in files}
    third_party = {k: v for k, v in import_roots.items() if k not in local_modules}
    detected = sorted({IMPORT_TECH[k] for k in third_party if k in IMPORT_TECH})

    all_routes = [dict(r, file=f["file"]) for f in files for r in f["routes"]]
    classes = [c for f in files for c in f["classes"]]
    pydantic_models = [c["name"] for c in classes if any(b.endswith(("BaseModel", "BaseSettings")) for b in c["bases"])]

    return {
        "python_files": len(files),
        "total_loc": sum(f["loc"] for f in files),
        "files": files,
        "third_party_imports": dict(Counter(third_party).most_common(40)),
        "technologies_from_imports": detected,
        "routes": all_routes,
        "entry_points": [f["file"] for f in files if f["entry_point"] or any(a["type"] in ("FastAPI", "Flask", "Streamlit") for a in f["app_objects"])],
        "app_objects": [dict(a, file=f["file"]) for f in files for a in f["app_objects"]],
        "dangerous_calls": [dict(d, file=f["file"]) for f in files for d in f["dangerous_calls"]],
        "env_vars": sorted({e for f in files for e in f["env_vars"]}),
        "function_count": sum(len(f["functions"]) + sum(len(c["methods"]) for c in f["classes"]) for f in files),
        "class_count": len(classes),
        "pydantic_models": pydantic_models,
        "syntax_errors": [{"file": f["file"], "error": f["syntax_error"]} for f in files if f["syntax_error"]],
        "high_complexity": sorted(
            [{"file": f["file"], "function": fn["name"], "complexity": fn["complexity"]}
             for f in files for fn in f["functions"] + [m for c in f["classes"] for m in c["methods"]]
             if fn["complexity"] >= 10], key=lambda x: -x["complexity"])[:20],
    }
