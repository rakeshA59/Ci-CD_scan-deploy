"""End-to-end orchestrator – the steps you see in the terminal:

 1 CHECKOUT       clone the GitHub repo (or copy a local folder)
 2 DISCOVERY      files, dependencies, AST facts -> tech stack (LLM or heuristic)
 3 CODE SCANNING  Bandit, Semgrep, pip-audit, Gitleaks, Ruff, Trivy
 4 SECURITY GATE  merge + triage findings, deterministic pass/fail
 5 UNIT TESTS     isolated venv, generate/repair tests, pytest + coverage, test gate
 6 PACKAGE        wheel/sdist or source bundle + SBOM
 7 CONTAINERIZE   Dockerfile, docker build, smoke run, Trivy image scan, container gate
 8 REPORT         HTML / Markdown / TXT / JSON
"""
from __future__ import annotations

import datetime as dt
import logging
import shutil
import time
from pathlib import Path

from cip import console as C
from cip.analyzer.ast_analyzer import analyze_ast
from cip.analyzer.dependency_analyzer import analyze_dependencies
from cip.analyzer.language_detector import detect_language
from cip.analyzer.llm_analyzer import analyze_application
from cip.analyzer.repository_scanner import scan_repository
from cip.container.container_scanner import scan_image
from cip.container.docker_builder import build_image, remove_old_images, smoke_run
from cip.container.dockerfile_generator import ensure_dockerignore, generate_dockerfile, health_path, lint_dockerfile
from cip.llm.client import LLMClient
from cip.packaging.python_packager import build_package
from cip.packaging.sbom_generator import generate_sbom
from cip.quality.quality_gate import container_gate, security_gate, test_gate
from cip.report.report_builder import write_reports
from cip.security.bandit_scanner import BanditScanner
from cip.security.base import SECURITY_CATEGORIES, SEVERITIES
from cip.security.dependency_scanner import PipAuditScanner
from cip.security.normalizer import normalize
from cip.security.quality_scanner import RuffScanner
from cip.security.secret_scanner import GitleaksScanner
from cip.security.semgrep_scanner import SemgrepScanner
from cip.security.triage import triage_findings
from cip.security.trivy_scanner import TrivyFsScanner
from cip.source.fetcher import describe, fetch_source, is_remote, normalise_url, repo_name
from cip.testing.test_analyzer import select_modules
from cip.testing.test_generator import GEN_DIR, dummy_env, generate_tests
from cip.testing.test_runner import TestEnvironment, prune_venvs, run_pytest
from cip.utils import docker_available, find_tool, write_json

log = logging.getLogger("cip.pipeline")

SCANNERS = {"bandit": BanditScanner, "semgrep": SemgrepScanner, "pip_audit": PipAuditScanner,
            "gitleaks": GitleaksScanner, "ruff": RuffScanner, "trivy_fs": TrivyFsScanner}
SCANNER_PURPOSE = {
    "bandit": "Python SAST – insecure code (eval, shell=True, pickle, weak crypto)",
    "semgrep": "SAST rules – injection, hard-coded JWT keys, CORS, debug mode",
    "pip-audit": "Dependency scan – known CVEs in requirements (PyPI advisory DB)",
    "gitleaks": "Secret scan – API keys, tokens, passwords in the code",
    "ruff": "Code quality – lint and likely bugs (non-blocking)",
    "trivy-fs": "Vulnerability + config scan – dependency CVEs with severity, Dockerfile misconfig",
}


class Pipeline:
    def __init__(self, source: str | Path, cfg: dict, output_root: Path, continue_on_fail: bool = False,
                 skip: set[str] | None = None, branch: str | None = None, ref: str | None = None):
        self.source_spec = str(source)
        self.branch, self.ref = branch, ref
        self.repo_name = repo_name(self.source_spec)
        self.cfg = cfg
        self.continue_on_fail = continue_on_fail
        self.skip = skip or set()
        self.run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run_dir = (output_root / f"{self.repo_name}-{self.run_id}").resolve()
        self.workspace = self.run_dir / "workspace"
        self.artifacts = self.run_dir / "artifacts"
        self.llm = LLMClient(cfg.get("llm", {}))
        self.state: dict = {
            "run_id": self.run_id, "source": self.source_spec, "run_dir": str(self.run_dir),
            "started_at": dt.datetime.now().isoformat(timespec="seconds"), "llm": self.llm.describe(),
            "stages": [], "gates": {}, "artifacts": [],
        }
        self._steps = self._plan_steps()
        self._step_no = 0

    # ------------------------------------------------------------------ helpers
    def _plan_steps(self) -> list[str]:
        steps = ["CHECKOUT", "DISCOVERY"]
        if "security" not in self.skip:
            steps += ["CODE SCANNING", "SECURITY TRIAGE & GATE"]
            if "tests" not in self.skip:
                steps.append("UNIT TESTS")
            steps.append("PACKAGE")
            if "container" not in self.skip and self.cfg.get("container", {}).get("enabled", True):
                steps.append("CONTAINERIZE")
        steps.append("REPORT")
        return steps

    def _step(self, title: str, purpose: str) -> None:
        self._step_no += 1
        C.banner(self._step_no, len(self._steps), title, purpose)

    def _stage(self, name: str, status: str, t0: float, **info) -> None:
        entry = {"stage": name, "status": status, "duration_s": round(time.time() - t0, 1), **info}
        self.state["stages"].append(entry)
        C.emit({"type": "stage", **entry})
        C.result(status, f"{name}: {status.upper()}  ({entry['duration_s']}s)"
                         + (f" – {info['message']}" if info.get("message") else ""))

    def _artifact(self, path: Path, kind: str) -> None:
        if path.exists():
            self.state["artifacts"].append({"kind": kind, "path": str(path.relative_to(self.run_dir)).replace("\\", "/")})

    def _gate(self, gate, stage_name: str) -> bool:
        """Print the gate checks; return True when the pipeline must stop here."""
        self.state["gates"][gate.gate] = gate.to_dict()
        C.emit({"type": "gate", **gate.to_dict()})
        C.action(f"{gate.gate.upper()} GATE (rules from config/pipeline.yaml – no AI involved)")
        for c in gate.checks:
            C.detail(c.line())
        for n in gate.notes:
            C.detail(f"note: {n[:200]}")
        status = "skipped" if gate.skipped else "passed" if gate.passed else "failed"
        self._stage(stage_name, status, time.time())
        blocked = not gate.passed and not self.continue_on_fail
        if not gate.passed:
            C.detail("→ stopping here (use --continue-on-fail to run the remaining steps anyway)" if blocked
                     else "→ continuing anyway because of --continue-on-fail")
        return blocked

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        t_all = time.time()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(exist_ok=True)
        handler = C.add_run_log(self.run_dir / "pipeline.log")
        C.emit({"type": "start", "run": self.run_dir.name, "repo": self.repo_name, "source": self.source_spec,
                "branch": self.branch, "ref": self.ref, "llm": self.llm.describe(), "steps": self._steps,
                "started_at": self.state["started_at"]})
        C.title(f"CIP run {self.run_id}  ·  {self.repo_name}")
        C.detail(f"source : {self.source_spec}" + (f"  (branch {self.branch})" if self.branch else "")
                 + (f"  (ref {self.ref})" if self.ref else ""))
        C.detail(f"LLM    : {self.llm.describe()}" + (f"   ({self.llm.note})" if getattr(self.llm, "note", "") else ""))
        C.detail(f"steps  : {' → '.join(self._steps)}")
        C.detail(f"output : {self.run_dir}")
        try:
            self._checkout()
            self._run_stages()
        except Exception as e:  # never lose the report
            log.error("Pipeline stopped: %s", e, exc_info=not isinstance(e, (RuntimeError, FileNotFoundError)))
            self.state["crash"] = f"{type(e).__name__}: {e}"
        if "overall" not in self.state:
            gates = list(self.state["gates"].values())
            if "crash" in self.state or any(not g["passed"] for g in gates) or len(gates) < self._expected_gates():
                self.state["overall"] = "FAIL"
            elif any(g.get("skipped") for g in gates):
                self.state["overall"] = "INCOMPLETE"   # nothing failed, but a stage could not run
            else:
                self.state["overall"] = "PASS"
        self.state["duration_s"] = round(time.time() - t_all, 1)
        self.state["llm_usage"] = {"calls": self.llm.calls, **self.llm.usage}
        self._report()
        logging.getLogger().removeHandler(handler)
        handler.close()
        return self.state

    def _expected_gates(self) -> int:
        return ("CODE SCANNING" in self._steps) + ("UNIT TESTS" in self._steps) + ("CONTAINERIZE" in self._steps)

    # ------------------------------------------------------------------ 1 checkout
    def _checkout(self) -> None:
        remote = is_remote(self.source_spec)
        self._step("CHECKOUT", "Get the code: git clone from GitHub" if remote else
                   "Get the code: copy the local folder (the original is never modified)")
        t0 = time.time()
        if remote:
            url = normalise_url(self.source_spec)
            C.action(f"git clone {url}" + (f"  --branch {self.branch}" if self.branch else "")
                     + (f"  then checkout {self.ref}" if self.ref else "  (latest commit only: --depth 1)"))
            C.detail(f"git: {find_tool('git') or 'NOT INSTALLED – will download the GitHub zip archive instead'}")
        else:
            C.action(f"copy {Path(self.source_spec).resolve()}  →  {self.workspace}")
        try:
            info = fetch_source(self.source_spec, self.workspace, self.branch, self.ref)
        except Exception as e:
            self._stage("checkout", "failed", t0, message=str(e)[:300])
            raise
        self.state["source_info"] = info
        C.emit({"type": "source", "info": info})
        if info.get("commit"):
            C.detail(f"commit : {info['commit'][:12]}  branch: {info.get('branch') or '-'}")
            C.detail(f"message: {info.get('commit_message', '')}  ({info.get('commit_author', '')}, {info.get('commit_date', '')})")
        self._stage("checkout", "passed", t0, message=describe(info))

    # ------------------------------------------------------------------ 2..7
    def _run_stages(self) -> None:
        # ---------------- 2 discovery
        self._step("DISCOVERY", "Understand the repo: files, dependencies, code structure → tech stack")
        t0 = time.time()
        C.action("repository_scanner: walking files, counting languages, finding key files")
        repo_scan = scan_repository(self.workspace)
        repo_scan["name"] = self.repo_name
        language = detect_language(repo_scan)
        C.detail(f"{repo_scan['total_files']} files · languages {language['languages']} · primary {language['primary_language']}")
        C.detail(f"key files: {', '.join(repo_scan['key_files'][:10]) or '-'}")
        C.action("dependency_analyzer: reading requirements*.txt / pyproject.toml")
        deps = analyze_dependencies(self.workspace)
        C.detail(f"{deps['dependency_count']} dependencies from {', '.join(deps['manifests']) or 'no manifest'} "
                 f"({len(deps['unpinned'])} not pinned)")
        for cat, items in deps["categories"].items():
            C.detail(f"{cat:<12} {', '.join(items)}")
        C.action("ast_analyzer: parsing every .py file (imports, routes, entry points, env vars, risky calls)")
        ast_info = analyze_ast(self.workspace)
        C.detail(f"{ast_info['python_files']} Python files · {ast_info['total_loc']} lines · "
                 f"{ast_info['function_count']} functions · {ast_info['class_count']} classes")
        C.detail(f"{len(ast_info['routes'])} HTTP routes · entry points: {', '.join(ast_info['entry_points']) or '-'}")
        for r in ast_info["routes"][:8]:
            C.detail(f"   {r['method']:<6} {r['path']:<32} {r['file']}:{r['line']}{'' if r.get('auth_dependency') else '   (no auth dependency)'}")
        if len(ast_info["routes"]) > 8:
            C.detail(f"   … {len(ast_info['routes']) - 8} more")
        if ast_info["dangerous_calls"]:
            C.detail(f"{len(ast_info['dangerous_calls'])} risky calls: " + ", ".join(
                f"{d['call']}@{d['file']}:{d['line']}" for d in ast_info["dangerous_calls"][:5]))
        self.evidence = {"repo": repo_scan, "language": language, "dependencies": deps, "ast": ast_info}
        write_json(self.artifacts / "evidence.json", self.evidence)
        self._artifact(self.artifacts / "evidence.json", "Deterministic evidence")
        self.state["discovery"] = {
            "language": language, "files": repo_scan["total_files"], "python_files": ast_info["python_files"],
            "loc": ast_info["total_loc"], "routes": ast_info["routes"], "dependency_count": deps["dependency_count"],
            "unpinned": deps["unpinned"], "categories": deps["categories"], "entry_points": ast_info["entry_points"],
            "env_vars": ast_info["env_vars"], "dangerous_calls": ast_info["dangerous_calls"],
            "high_complexity": ast_info["high_complexity"], "syntax_errors": ast_info["syntax_errors"],
            "existing_tests": len(repo_scan["test_files"]), "tree": repo_scan["tree"],
        }
        if not language["supported"]:
            self._stage("discovery", "failed", t0, message=f"Primary language {language['primary_language']} not supported in V1")
            raise RuntimeError(f"Unsupported primary language: {language['primary_language']}")

        C.action(f"application analysis with {'LLM ' + self.llm.describe() if self.llm.enabled else 'heuristic rules (no LLM)'}")
        self.app = analyze_application(self.evidence, self.workspace, self.llm)
        self.state["application"] = self.app
        write_json(self.artifacts / "application_analysis.json", self.app)
        self._artifact(self.artifacts / "application_analysis.json", "Application analysis")
        for label, key in (("Application", "application_name"), ("Type", "application_type"), ("Language", "language"),
                           ("Frameworks", "frameworks"), ("Databases", "databases"), ("Auth", "authentication"),
                           ("Integrations", "external_integrations"), ("Architecture", "architecture_style"),
                           ("Purpose", "purpose")):
            v = self.app.get(key)
            C.detail(f"{label:<13}: {', '.join(v) if isinstance(v, list) else v or '-'}")
        self._stage("discovery", "passed", t0, message=f"analysis by {self.app.get('generated_by', '')}")
        if "security" in self.skip:          # `cip analyze` = discovery only
            self.state["overall"] = "ANALYSIS ONLY"
            return

        # ---------------- 3 code scanning
        self._step("CODE SCANNING", "Static analysis, vulnerability & dependency scan, secrets, lint (6 tools)")
        t0 = time.time()
        sec_cfg = self.cfg.get("security", {})
        enabled = sec_cfg.get("scanners", {})
        results = []
        for key, cls in SCANNERS.items():
            if not enabled.get(key, True):
                continue
            scanner = cls(sec_cfg, self.artifacts / "raw")
            C.action(f"{scanner.name:<10} {SCANNER_PURPOSE.get(scanner.name, '')}")
            r = scanner.scan(self.workspace)
            C.command(r.command)
            counts = {s: sum(1 for f in r.findings if f.severity == s) for s in SEVERITIES}
            if r.status in ("skipped", "error"):
                C.result(r.status, f"{r.scanner}: {r.status.upper()} – {r.message[:200]}")
            else:
                C.result(r.status, f"{r.scanner}: {len(r.findings)} findings  {C.sev_line(counts)}  ({r.duration_s:.1f}s)"
                         + (f"  note: {r.message[:120]}" if r.message else ""))
            results.append(r)
        security = normalize(results)
        s = security["summary"]
        C.action("normalizer: merging duplicates into one list with one format")
        C.detail(f"{s['total']} unique findings · security {s['security_total']} ({C.sev_line(s['by_severity'])}) · "
                 f"code quality {s['code_quality']}")
        C.detail(f"by category: {s['by_category']}")
        self._stage("code_scanning", "passed", t0, message=f"{s['total']} findings, raw outputs in artifacts/raw/")

        # ---------------- 4 triage + gate
        self._step("SECURITY TRIAGE & GATE", "Explain & prioritise findings, then decide pass/fail from numbers only")
        t0 = time.time()
        C.action(f"triage with {'LLM ' + self.llm.describe() if self.llm.enabled else 'rule-based remediation table (no LLM)'}")
        overview = triage_findings(security["findings"], self.workspace, self.llm, self.app,
                                   sec_cfg.get("max_findings_for_llm_triage", 25))
        security["triage"] = overview
        top = [f for f in security["findings"] if f.category in SECURITY_CATEGORIES and f.severity in ("CRITICAL", "HIGH")]
        if overview.get("executive_summary"):
            C.detail(overview["executive_summary"][:400])
        for f in top[:10]:
            C.detail(f"{f.id} {f.severity:<8} {f.category:<10} {f.file}:{f.line}  {f.title[:60]}")
        if len(top) > 10:
            C.detail(f"… {len(top) - 10} more critical/high findings – see the HTML report")
        security["findings"] = [f.to_dict() for f in security["findings"]]
        self.state["security"] = security
        write_json(self.artifacts / "security_report.json", security)
        self._artifact(self.artifacts / "security_report.json", "Unified security report")
        self._stage("triage", "passed", t0, message=f"source: {overview.get('source')}")
        gate = security_gate(security, self.cfg.get("quality_gate", {}).get("security", {}))
        if self._gate(gate, "security_gate"):
            self.state["stopped_at"] = "security_gate"
            return

        # ---------------- 5 unit tests
        if "tests" not in self.skip:
            self._step("UNIT TESTS", "Isolated env → run repo's tests + generated tests → coverage → test gate")
            self._testing()
            gate = test_gate(self.state["testing"], self.cfg.get("quality_gate", {}).get("testing", {}))
            if self._gate(gate, "test_gate"):
                self.state["stopped_at"] = "test_gate"
                return

        # ---------------- 6 package
        self._step("PACKAGE", "Build the deployable: wheel + sdist (library) or source bundle (app), plus SBOM")
        t0 = time.time()
        gen = self.workspace / GEN_DIR
        if gen.exists():
            shutil.rmtree(gen)  # generated tests are a deliverable (artifacts/), but never ship in the package/image
        pkg_cfg = self.cfg.get("packaging", {})
        is_lib = (self.workspace / "pyproject.toml").exists() or (self.workspace / "setup.py").exists()
        C.action("python -m build --wheel --sdist" if is_lib else "no pyproject/setup.py → zip a clean source bundle")
        pkg = build_package(self.workspace, self.artifacts / "dist", pkg_cfg.get("build_wheel", True), self.repo_name)
        for a in pkg["artifacts"]:
            self._artifact(self.artifacts / "dist" / a, "Package")
            C.detail(f"artifacts/dist/{a}")
        if pkg_cfg.get("sbom", True):
            C.action("trivy fs --format cyclonedx  (SBOM = list of every component in the package)")
            pkg["sbom"] = generate_sbom("", self.artifacts / "sbom.cdx.json", self.workspace, "fs")
            C.detail(f"SBOM: {pkg['sbom'].get('status')} {pkg['sbom'].get('components', '')} components {pkg['sbom'].get('message', '')[:150]}")
            self._artifact(self.artifacts / "sbom.cdx.json", "SBOM (CycloneDX, source)")
        self.state["packaging"] = pkg
        self._stage("package", "warning" if pkg.get("build_error") else "passed", t0, message=pkg["message"][:160])

        # ---------------- 7 containerize
        if "container" not in self.skip and self.cfg.get("container", {}).get("enabled", True):
            self._step("CONTAINERIZE", "Dockerfile → docker build → start-up check → Trivy image scan → container gate")
            self._container()
            gate = container_gate(self.state["container"], self.cfg.get("quality_gate", {}).get("container", {}))
            self._gate(gate, "container_gate")

    # ------------------------------------------------------------------ 5 testing
    def _testing(self) -> None:
        tcfg = self.cfg.get("testing", {})
        t0 = time.time()
        C.action("preparing an isolated Python environment with the repo's dependencies + pytest")
        prune_venvs(max(1, int(tcfg.get("max_cached_envs", 3))) - 1)  # make room for this run's env
        free_gb = shutil.disk_usage(self.run_dir).free / 1e9
        C.detail(f"free disk space: {free_gb:.1f} GB")
        if free_gb < 3:
            log.warning("Only %.1f GB free on this drive – installing dependencies may fail with 'No space left "
                        "on device'. Free space or run: python -m cip.cli clean", free_gb)
        tenv = TestEnvironment(self.workspace, tcfg.get("use_venv", True))
        ok = tenv.prepare()
        for line in tenv.install_log:
            C.detail(line[:300])
        if not ok:
            self.state["testing"] = {"total": 0, "passed": 0, "error": tenv.error, "install_log": tenv.install_log}
            self._stage("test_environment", "failed", t0, message=tenv.error[:300])
            return
        self._stage("test_environment", "passed", t0, message=tenv.python)
        existing = self.state["discovery"]["existing_tests"]
        C.detail(f"repo already has {existing} test file(s)")

        gen_report = {}
        env_vars = self.evidence["ast"]["env_vars"]
        if tcfg.get("generate_tests", True):
            t0 = time.time()
            modules = select_modules(self.evidence["ast"], tcfg.get("max_modules_for_generation", 15))
            C.action(f"generating tests for {len(modules)} module(s) with "
                     f"{'LLM – each file is run, repaired up to ' + str(tcfg.get('max_repair_attempts', 2)) + 'x, failing tests pruned' if self.llm.enabled else 'offline smoke tests (no LLM)'}")
            gen_report = generate_tests(self.workspace, modules, tenv, self.llm, self.app, self.artifacts / "tests",
                                        env_vars, tcfg.get("max_repair_attempts", 2))
            for f in gen_report["files"]:
                extra = f" ({f.get('passed', 0)} passed{', ' + str(f['xfailed']) + ' suspected defects' if f.get('xfailed') else ''}" \
                        f"{', ' + str(f['attempts']) + ' repair(s)' if f.get('attempts') else ''})" if f["status"] == "ok" else ""
                if f["status"] == "failing":
                    extra = f" ({f.get('passed', 0)} passed, {f.get('failed', 0)} failed – kept: this is a real app error)"
                C.detail(f"{'✔' if f['status'] == 'ok' else '✘'} {f.get('mode', 'llm'):<5} {f['module']:<36} {f['status']}{extra}")
            for st in gen_report.get("stubbed_imports", []):
                C.detail(f"⚠ {st['file']} fakes {', '.join(st['modules'])} – its passes don't prove those imports work")
            for rf in gen_report.get("runtime_failures", []):
                C.detail(f"⚑ app is broken at runtime ({rf['module']}): {rf['error'].splitlines()[0][:220]}")
            for d in gen_report.get("suspected_defects", []):
                C.detail(f"⚑ suspected defect in {d['module']}: {d['defect']}")
            gen_report["selected_modules"] = [{"module": m["module"], "score": m["score"],
                                               "has_existing_tests": m["has_existing_tests"],
                                               "scenarios": m["scenarios"]} for m in modules]
            self._stage("test_generation", "passed" if gen_report["generated_ok"] else "warning", t0,
                        message=f"{gen_report['generated_ok']}/{len(modules)} files passing, "
                                f"{sum(1 for f in gen_report['files'] if f['status'] == 'failing')} failing (real app errors), "
                                f"{len(gen_report['quarantined'])} quarantined, {len(gen_report['removed_tests'])} tests pruned")

        t0 = time.time()
        C.action("pytest --cov  (existing + generated tests, full suite)")
        result = run_pytest(tenv, [], self.artifacts / "tests", "full", coverage=True,
                            timeout=tcfg.get("pytest_timeout_seconds", 900), extra_env=dummy_env(env_vars))
        result["generation"] = gen_report
        result["install_log"] = tenv.install_log
        self.state["testing"] = result
        C.detail(f"passed {result['passed']} · failed {result['failed']} · errors {result['errors']} · "
                 f"skipped {result['skipped']} · xfail {result['xfailed']} · coverage {result.get('coverage_percent')}%")
        for f in result["failures"][:5]:
            C.detail(f"✘ {f['test']}: {(f['message'].splitlines() or [''])[0][:160]}")
        if result.get("error"):
            C.detail(result["error"][:400])
        gen = self.workspace / GEN_DIR
        if gen.exists():
            shutil.copytree(gen, self.artifacts / "generated_tests", dirs_exist_ok=True)
            self._artifact(self.artifacts / "generated_tests", "Generated pytest tests")
        for name, kind in (("full.junit.xml", "JUnit test report"), ("coverage.json", "Coverage (JSON)"),
                           ("htmlcov", "Coverage (HTML)")):
            self._artifact(self.artifacts / "tests" / name, kind)
        status = "passed" if result["total"] and not (result["failed"] or result["errors"]) else "failed"
        self._stage("test_execution", status, t0, message=f"{result['passed']}/{result['total']} passed, "
                    f"coverage {result.get('coverage_percent')}%")

    # ------------------------------------------------------------------ 7 container
    def _container(self) -> None:
        ccfg = self.cfg.get("container", {})
        t0 = time.time()
        out: dict = {}
        self.state["container"] = out
        df = self.workspace / "Dockerfile"
        is_library = (not df.exists() and not self.evidence["ast"]["app_objects"]
                      and not self.evidence["ast"]["entry_points"])
        if is_library:
            out.update(status="skipped", message="library package (no app / entry point, no Dockerfile) – "
                                                 "the wheel in artifacts/dist is the deployable")
            self._stage("dockerfile", "skipped", t0, message=out["message"])
            return
        if df.exists():
            C.action("using the repository's own Dockerfile")
            out["dockerfile_source"] = "repository"
            if ensure_dockerignore(self.workspace):
                out["dockerignore_generated"] = True
                C.detail("no .dockerignore found – generated one (keeps .env, .git, tests out of the image)")
        elif ccfg.get("generate_dockerfile_if_missing", True):
            C.action("no Dockerfile in repo → generating a hardened one (slim base, non-root user, healthcheck)")
            out.update(generate_dockerfile(self.workspace, self.evidence, ccfg.get("base_image", "python:3.12-slim")))
            out["dockerfile_source"] = "generated"
            C.detail(f"start command: {' '.join(out.get('start_command', []))}")
        else:
            out.update(status="skipped", message="no Dockerfile and generation disabled")
            self._stage("dockerfile", "skipped", t0, message=out["message"])
            return
        shutil.copy(df, self.artifacts / "Dockerfile")
        self._artifact(self.artifacts / "Dockerfile", f"Dockerfile ({out['dockerfile_source']})")
        C.action("Dockerfile lint (root user, .env copied, secrets in ENV, unpinned base, …)")
        out["dockerfile_lint"] = lint_dockerfile(df, self.workspace)
        out["dockerfile"] = df.read_text(encoding="utf-8")
        for i in out["dockerfile_lint"]["issues"]:
            C.detail(f"{i['severity']:<6} {i['rule']} {i['message']}")
        self._stage("dockerfile", "passed" if not out["dockerfile_lint"]["high"] else "warning", t0,
                    message=f"{out['dockerfile_source']}; lint H/M/L = {out['dockerfile_lint']['high']}/"
                            f"{out['dockerfile_lint']['medium']}/{out['dockerfile_lint']['low']}")

        if not docker_available():
            out.update(status="skipped", message="Docker is not running – Dockerfile produced but image not built "
                                                 "(start Docker Desktop to build, run and scan the image)")
            self._stage("docker_build", "skipped", time.time(), message=out["message"])
            return
        t0 = time.time()
        image = ccfg.get("image_name") or f"{self.repo_name.lower().replace('_', '-').replace(' ', '-')}:{self.run_id}"
        C.action(f"docker build -t {image} .")
        out.update(build_image(self.workspace, image, self.artifacts / "docker_build.log"))
        self._artifact(self.artifacts / "docker_build.log", "Docker build log")
        self._stage("docker_build", "passed" if out["image_built"] else "failed", t0,
                    message=f"{image} ({out.get('size_mb')} MB)" if out["image_built"] else out["message"][-300:])
        if not out["image_built"]:
            return
        removed = remove_old_images(image)
        if removed:
            C.detail(f"removed {len(removed)} older image(s) of this repo to save disk space: {', '.join(removed)}")

        t0 = time.time()
        port = out.get("port") or next((int(p.split("/")[0]) for p in out["dockerfile_lint"]["exposed_ports"] if p.split("/")[0].isdigit()), 0)
        probe = health_path(self.evidence)
        C.action(f"smoke run: docker run {image}, wait 12s, check it is still up"
                 + (f", then call http://127.0.0.1:{port}{probe}" if port and probe else ""))
        out["smoke"] = smoke_run(image, port, dummy_env(self.evidence["ast"]["env_vars"]), probe_path=probe)
        if out["smoke"]["status"] != "passed":
            C.detail("container logs (tail):")
            C.detail(out["smoke"].get("logs_tail", "")[-800:])
        self._stage("container_smoke_run", "passed" if out["smoke"]["status"] == "passed" else "warning", t0,
                    message=f"running={bool(out['smoke'].get('running_after_s'))} http={out['smoke'].get('http_probe')}")

        t0 = time.time()
        C.action(f"trivy image {image}  (OS + library CVEs and secrets inside the image)")
        free_gb = shutil.disk_usage(self.run_dir).free / 1e9
        need_gb = (out.get("size_mb") or 1000) / 1000 * 1.5
        if free_gb < need_gb:
            log.warning("Only %.1f GB free – Trivy needs about %.1f GB to unpack this image; the scan may fail "
                        "with 'not enough space'. Run: python -m cip.cli clean", free_gb, need_gb)
        out["scan"] = scan_image(image, self.artifacts / "raw" / "trivy-image.json", self.workspace)
        self._artifact(self.artifacts / "raw" / "trivy-image.json", "Container scan (Trivy)")
        if self.cfg.get("packaging", {}).get("sbom", True):
            out["sbom"] = generate_sbom(image, self.artifacts / "sbom-image.cdx.json", self.workspace, "image")
            self._artifact(self.artifacts / "sbom-image.cdx.json", "SBOM (CycloneDX, image)")
        sev = out["scan"].get("by_severity", {})
        self._stage("container_scan", "passed" if out["scan"]["status"] == "ok" else "warning", t0,
                    message=f"{C.sev_line(sev)} · OS {out['scan'].get('os', '')}" if out["scan"]["status"] == "ok"
                    else out["scan"].get("message", "")[:200])

    # ------------------------------------------------------------------ 8 report
    def _report(self) -> None:
        self._step_no = len(self._steps) - 1
        self._step("REPORT", "Write HTML / Markdown / TXT / JSON and summarise")
        paths = write_reports(self.state, self.run_dir)
        self.state["reports"] = paths
        C.table([[s["stage"], s["status"].upper(), f"{s['duration_s']}s", str(s.get("message", ""))[:60]]
                 for s in self.state["stages"]], ["stage", "status", "time", "detail"])
        if self.state.get("stopped_at"):
            C.detail(f"stopped at {self.state['stopped_at']} – later steps did not run")
        C.detail(f"HTML report : {paths['html']}")
        C.detail(f"run log     : {self.run_dir / 'pipeline.log'}")
        C.title(f"OVERALL: {self.state['overall']}   ({self.state['duration_s']}s, LLM calls {self.llm.calls})")
        rel = {k: str(Path(v).relative_to(self.run_dir.parent)).replace("\\", "/") for k, v in paths.items()}
        C.emit({"type": "done", "overall": self.state["overall"], "duration_s": self.state["duration_s"],
                "reports": rel, "stopped_at": self.state.get("stopped_at"), "crash": self.state.get("crash"),
                "summary": _summary(self.state)})


def _summary(state: dict) -> dict:
    """Small numbers for the UI's result cards."""
    sec = (state.get("security") or {}).get("summary", {})
    t = state.get("testing") or {}
    c = state.get("container") or {}
    app = state.get("application") or {}
    return {
        "app_type": app.get("application_type"), "frameworks": app.get("frameworks"),
        "security_by_severity": sec.get("by_severity"), "findings": sec.get("security_total"),
        "code_quality": sec.get("code_quality"), "security_gate": (state.get("gates") or {}).get("security", {}).get("passed"),
        "tests_passed": t.get("passed"), "tests_total": t.get("total"), "coverage": t.get("coverage_percent"),
        "image": c.get("image"), "image_vulns": (c.get("scan") or {}).get("by_severity") or None,
        "image_scan": (c.get("scan") or {}).get("status"), "container_note": c.get("message"),
        "packages": (state.get("packaging") or {}).get("artifacts"),
    }
