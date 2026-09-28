"""Isolated test environment + pytest/coverage execution and result parsing."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from cip.config import PROJECT_ROOT
from cip.utils import CmdResult, run_cmd

log = logging.getLogger("cip.testing")

ENV_RECIPE_VERSION = "3"
TEST_TOOLS = ["pytest", "pytest-cov", "pytest-asyncio", "pytest-timeout", "httpx", "mongomock", "anyio"]

COVERAGERC = """[run]
source = .
branch = true
omit =
    tests/*
    */tests/*
    test_*.py
    */test_*.py
    conftest.py
    */conftest.py
    setup.py
    .venv/*
    venv/*
    */migrations/*
"""


def _pip_error_summary(output: str) -> str:
    """Pick the lines of pip output that explain a failure (e.g. a package with no wheel for this Python)."""
    keys = ("error:", "ERROR:", "No matching distribution", "Could not find a version", "Failed building wheel",
            "failed-wheel-build", "requires a different Python", "Microsoft Visual C++", "metadata-generation-failed")
    lines = [l.strip() for l in output.splitlines() if any(k in l for k in keys)]
    summary = " | ".join(dict.fromkeys(lines))[:1200]
    if "Failed building wheel" in output or "metadata-generation-failed" in output or "Visual C++" in output:
        summary += (f" | HINT: a pinned package has no pre-built wheel for Python "
                    f"{sys.version_info.major}.{sys.version_info.minor}; upgrade that pin or run CIP with an older Python.")
    return summary or output[-1200:]


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def prune_venvs(keep: int = 3) -> list[str]:
    """Delete the least recently used cached test virtualenvs (each can be several hundred MB)."""
    root = PROJECT_ROOT / ".cip" / "venvs"
    if not root.is_dir():
        return []
    envs = sorted((d for d in root.iterdir() if d.is_dir()),
                  key=lambda d: (d / ".cip_ready").stat().st_mtime if (d / ".cip_ready").exists() else 0, reverse=True)
    removed = []
    for d in envs[keep:]:
        shutil.rmtree(d, ignore_errors=True)
        removed.append(d.name)
    if removed:
        log.info("Removed %d old test environment(s) to save disk space: %s", len(removed), ", ".join(removed))
    return removed


class TestEnvironment:
    """A cached virtualenv keyed on the target repo's requirement files."""

    def __init__(self, workspace: Path, use_venv: bool = True):
        self.workspace = workspace
        self.use_venv = use_venv
        self.python = sys.executable
        self.install_log: list[str] = []
        self.error = ""

    def _req_files(self) -> list[Path]:
        """Runtime + test requirement files in the usual places (requirements*.txt, requirements/…, test-requirements.txt …)."""
        ws = self.workspace
        found = set(ws.glob("requirements*.txt")) | set(ws.glob("*requirements*.txt"))
        for d in ("requirements", "reqs", "requirements.d"):
            if (ws / d).is_dir():
                found |= {p for p in (ws / d).glob("*.txt")
                          if not any(k in p.name for k in ("docs", "doc.", "typing", "build", "lint", "style"))}
        return sorted(found)

    def _project_name(self) -> str:
        pp = self.workspace / "pyproject.toml"
        if pp.exists():
            try:
                import tomllib
                data = tomllib.loads(pp.read_text(encoding="utf-8"))
                return data.get("project", {}).get("name") or data.get("tool", {}).get("poetry", {}).get("name") or ""
            except Exception:
                return ""
        return ""

    def _pyproject_test_extras(self) -> tuple[list[str], list[str]]:
        """(optional-dependency extras to install, dependency-group packages) that look test-related."""
        pp = self.workspace / "pyproject.toml"
        if not pp.exists():
            return [], []
        try:
            import tomllib
            data = tomllib.loads(pp.read_text(encoding="utf-8"))
        except Exception:
            return [], []
        wanted = ("test", "tests", "testing", "dev")
        extras = [k for k in (data.get("project", {}).get("optional-dependencies") or {}) if k.lower() in wanted]
        groups = data.get("dependency-groups") or {}
        pkgs: list[str] = []

        def expand(name: str, seen: set):
            for item in groups.get(name, []):
                if isinstance(item, str):
                    pkgs.append(item)
                elif isinstance(item, dict) and item.get("include-group") and item["include-group"] not in seen:
                    seen.add(item["include-group"])
                    expand(item["include-group"], seen)
        for g in groups:
            if g.lower() in wanted:
                expand(g, {g})
        return extras, sorted(set(pkgs))

    def prepare(self) -> bool:
        if not self.use_venv:
            return True
        reqs = self._req_files()
        h = hashlib.sha256(ENV_RECIPE_VERSION.encode())  # bump when install logic changes -> fresh venvs
        for r in reqs:
            h.update(r.read_bytes())
        for f in ("pyproject.toml", "setup.py", "setup.cfg"):
            if (self.workspace / f).exists():
                h.update((self.workspace / f).read_bytes())
        venv = PROJECT_ROOT / ".cip" / "venvs" / h.hexdigest()[:16]
        py = venv_python(venv)
        marker = venv / ".cip_ready"
        if marker.exists() and not run_cmd([str(py), "-m", "pip", "--version"], timeout=60).ok:
            log.warning("Cached test virtualenv %s is broken – rebuilding", venv)
            marker.unlink()
        if not marker.exists():
            if venv.exists():
                # A previous attempt died half-way (e.g. a broken pip) – start clean.
                shutil.rmtree(venv, ignore_errors=True)
            log.info("Creating test virtualenv %s (first run for this dependency set – may take a few minutes)", venv)
            r = run_cmd([sys.executable, "-m", "venv", str(venv)], timeout=300)
            if not r.ok:
                self.error = f"venv creation failed: {r.stderr[-400:]}"
                return False
            # NOTE: deliberately no `pip install --upgrade pip` – on Windows that can leave pip half-replaced
            # ("No module named 'pip._internal.cli'").
            pip = [str(py), "-m", "pip", "install", "-q", "--disable-pip-version-check", "--prefer-binary"]
            for req in reqs:
                r = run_cmd(pip + ["-r", str(req)], cwd=self.workspace, timeout=1800)
                self.install_log.append(f"{req.name}: {'ok' if r.ok else 'FAILED'}")
                if not r.ok:
                    # Continue: partial installs still allow many tests to run; errors surface in pytest.
                    detail = _pip_error_summary(r.stdout + r.stderr)
                    self.install_log.append(detail)
                    log.warning("Installing %s failed – continuing. %s", req.name, detail)
            if (self.workspace / "pyproject.toml").exists() or (self.workspace / "setup.py").exists():
                extras, group_pkgs = self._pyproject_test_extras()
                target = "." + (f"[{','.join(extras)}]" if extras else "")
                # Install the project (to pull in its dependencies + test extras), then remove the project
                # itself: the venv is cached across runs, so the code under test must always come from THIS
                # run's checkout (via PYTHONPATH), never from a stale installed copy.
                r = run_cmd(pip + [target], cwd=self.workspace, timeout=1800)
                self.install_log.append(f"project dependencies ({target}): {'ok' if r.ok else 'FAILED'}")
                if not r.ok:
                    self.install_log.append(_pip_error_summary(r.stdout + r.stderr))
                name = self._project_name()
                if name:
                    run_cmd([str(py), "-m", "pip", "uninstall", "-y", "-q", name], timeout=300)
                if group_pkgs:
                    r = run_cmd(pip + group_pkgs, cwd=self.workspace, timeout=1800)
                    self.install_log.append(f"dependency-groups (test/dev): {'ok' if r.ok else 'FAILED'}")
            tools = list(TEST_TOOLS)
            if self._needs_old_httpx(py):
                # Starlette's TestClient before 0.42 breaks with httpx>=0.28 ("unexpected keyword 'app'").
                tools = [t if t != "httpx" else "httpx<0.28" for t in tools]
                self.install_log.append("pinned httpx<0.28 for older Starlette TestClient compatibility")
            r = run_cmd(pip + tools, timeout=900)
            if not r.ok:
                self.error = f"installing test tooling failed: {_pip_error_summary(r.stdout + r.stderr)}"
                return False
            marker.write_text("ok")
        else:
            log.info("Reusing cached test virtualenv %s", venv)
            marker.touch()  # remember it was used recently (pruning keeps the most recently used)
        self.python = str(py)
        return True

    @staticmethod
    def _needs_old_httpx(py: Path) -> bool:
        r = run_cmd([str(py), "-c", "import starlette;print(starlette.__version__)"], timeout=60)
        if not r.ok:
            return False
        try:
            parts = tuple(int(x) for x in r.stdout.strip().split(".")[:2])
        except ValueError:
            return False
        return parts < (0, 42)

    def env(self, extra_env: dict | None = None) -> dict:
        paths = [str(self.workspace)]
        if (self.workspace / "src").is_dir():      # "src layout" projects
            paths.insert(0, str(self.workspace / "src"))
        env = {"PYTHONPATH": os.pathsep.join(paths + [os.environ.get("PYTHONPATH", "")]),
               "PYTHONDONTWRITEBYTECODE": "1", "CIP_TESTING": "1"}
        env.update(extra_env or {})
        return env


def run_pytest(tenv: TestEnvironment, targets: list[str], out_dir: Path, name: str,
               coverage: bool = False, timeout: int = 900, extra_env: dict | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    junit = out_dir / f"{name}.junit.xml"
    cmd = [tenv.python, "-m", "pytest", *targets, "-q", "-p", "no:cacheprovider", "--tb=short",
           f"--junitxml={junit}", "-o", "junit_family=xunit2",
           "--continue-on-collection-errors"]  # one broken test module must not hide all the others
    if tenv.use_venv or importlib.util.find_spec("pytest_timeout"):
        cmd.append("--timeout=120")
    if coverage:
        rc = tenv.workspace / ".coveragerc"
        rc.write_text(COVERAGERC, encoding="utf-8")
        cov_json = out_dir / "coverage.json"
        cmd += ["--cov=.", f"--cov-config={rc}", f"--cov-report=json:{cov_json}",
                f"--cov-report=html:{out_dir / 'htmlcov'}", "--cov-report=term"]
    res: CmdResult = run_cmd(cmd, cwd=tenv.workspace, timeout=timeout, env=tenv.env(extra_env))
    (out_dir / f"{name}.log").write_text(res.stdout + "\n" + res.stderr, encoding="utf-8")
    result = parse_junit(junit)
    result["returncode"] = res.returncode
    result["output_tail"] = (res.stdout + res.stderr)[-4000:]
    if coverage:
        result.update(parse_coverage(out_dir / "coverage.json"))
    if res.skipped:
        result["error"] = res.skip_reason
    elif result["total"] == 0 and res.returncode not in (0, 5):
        result["error"] = f"pytest failed to run (exit {res.returncode}): {(res.stdout + res.stderr)[-800:]}"
    return result


def parse_junit(path: Path) -> dict:
    out = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 0, "failures": []}
    if not path.exists():
        return out
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return out
    for tc in root.iter("testcase"):
        out["total"] += 1
        tag = next((c.tag for c in tc if c.tag in ("failure", "error", "skipped")), None)
        test_id = f"{tc.get('classname')}::{tc.get('name')}"
        if tag == "failure":
            out["failed"] += 1
            node = tc.find("failure")
            out["failures"].append({"test": test_id, "message": (node.get("message") or "")[:300],
                                    "detail": (node.text or "")[-1500:]})
        elif tag == "error":
            out["errors"] += 1
            node = tc.find("error")
            out["failures"].append({"test": test_id, "message": (node.get("message") or "")[:300],
                                    "detail": (node.text or "")[-1500:]})
        elif tag == "skipped":
            node = tc.find("skipped")
            if node is not None and "xfail" in (node.get("type", "") + (node.get("message") or "")).lower():
                out["xfailed"] += 1
            else:
                out["skipped"] += 1
        else:
            out["passed"] += 1
    # skipped/xfailed tests are not counted against pass rate
    out["total"] = out["passed"] + out["failed"] + out["errors"]
    return out


def parse_coverage(path: Path) -> dict:
    if not path.exists():
        return {"coverage_percent": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    files = {f: round(v["summary"]["percent_covered"], 1) for f, v in data.get("files", {}).items()}
    return {"coverage_percent": round(data["totals"]["percent_covered"], 1),
            "coverage_by_file": dict(sorted(files.items(), key=lambda kv: kv[1]))}
