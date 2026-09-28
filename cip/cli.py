"""Command line entry point.

    python -m cip.cli run   <github-url | org/repo | local-path> [--branch B] [--ref SHA]
                            [--continue-on-fail] [--skip tests,container] [--no-llm]
    python -m cip.cli analyze <repo-path>        # Phase 1 only
    python -m cip.cli scan    <repo-path>        # Phase 1-4 (analysis + security + gate)
    python -m cip.cli doctor                     # which tools are available + live LLM test
    python -m cip.cli clean [--keep-runs 5] [--all-envs]   # free disk space
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cip.config import PROJECT_ROOT, load_config
from cip.console import setup as setup_logging
from cip.utils import docker_available, find_tool

TOOLS = ["git", "bandit", "semgrep", "pip-audit", "gitleaks", "ruff", "trivy", "docker"]


def doctor(cfg: dict) -> int:
    from cip.llm.client import LLMClient
    print(f"Python:  {sys.version.split()[0]} ({sys.executable})")
    for t in TOOLS:
        p = find_tool(t)
        print(f"  {t:<10} {'OK  ' + p if p else 'MISSING'}")
    print(f"  docker daemon: {'running' if docker_available() else 'not available'}")
    print("  (missing semgrep/gitleaks/trivy fall back to their Docker images when the daemon is running)")
    llm = LLMClient(cfg.get('llm', {}))
    keys = [v for v in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY") if os.getenv(v, "").strip()]
    print(f"LLM:     {llm.describe()}   (keys found in .env/environment: {', '.join(keys) or 'none'}; "
          f"LLM_PROVIDER={os.getenv('LLM_PROVIDER') or 'auto'})")
    if getattr(llm, "note", ""):
        print(f"  note: {llm.note}")
    if llm.enabled:
        try:
            reply = llm.complete("Reply with the single word: pong", "ping", max_tokens=20)
            print(f"  live test call: OK (model answered {reply.strip()[:30]!r})")
        except Exception as e:
            print(f"  live test call: FAILED – {e}")
            print("  check: API key valid? model name correct for your account (LLM_MODEL in .env)? "
                  "`pip install -U anthropic openai`?")
    import shutil
    free = shutil.disk_usage(PROJECT_ROOT).free / 1e9
    print(f"Disk:    {free:.1f} GB free on this drive" + ("   ⚠ low – run `python -m cip.cli clean`" if free < 3 else ""))
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    print(f"GitHub:  {'token set (private repos OK)' if token else 'no GITHUB_TOKEN – public repos only'}")
    return 0


def clean(keep_runs: int, all_envs: bool) -> int:
    import shutil
    from cip.testing.test_runner import prune_venvs

    def size(p: Path) -> float:
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1e6
    freed = 0.0
    runs = PROJECT_ROOT / "runs"
    if runs.is_dir():
        dirs = sorted((d for d in runs.iterdir() if d.is_dir()), key=lambda d: d.stat().st_mtime, reverse=True)
        for d in dirs[keep_runs:]:
            freed += size(d)
            shutil.rmtree(d, ignore_errors=True)
            print(f"  removed run {d.name}")
    venvs = PROJECT_ROOT / ".cip" / "venvs"
    before = size(venvs) if venvs.is_dir() else 0
    prune_venvs(0 if all_envs else 2)
    freed += before - (size(venvs) if venvs.is_dir() else 0)
    if find_tool("docker") and docker_available():
        import subprocess
        # images CIP built: keep only the newest tag of each repo, then drop dangling layers + build cache
        rows = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.CreatedAt}}"],
                              capture_output=True, text=True).stdout.splitlines()
        by_repo: dict[str, list] = {}
        for r in rows:
            ref, created = r.split(" ", 1)
            repo, tag = ref.rsplit(":", 1)
            if len(tag) == 15 and tag[8] == "-" and tag.replace("-", "").isdigit():   # CIP tag: yyyymmdd-hhmmss
                by_repo.setdefault(repo, []).append(ref)
        for repo, refs in by_repo.items():
            for ref in sorted(refs)[:-1]:
                subprocess.run(["docker", "rmi", "-f", ref], capture_output=True)
                print(f"  removed image {ref}")
        subprocess.run(["docker", "image", "prune", "-f"], capture_output=True)
        subprocess.run(["docker", "builder", "prune", "-f"], capture_output=True)
        print("  pruned dangling images and Docker build cache")
    print(f"Freed {freed:,.0f} MB. Disk now: {shutil.disk_usage(PROJECT_ROOT).free / 1e9:.1f} GB free.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cip", description="Code Intelligence Platform – assess, test, package and containerise a Python repo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "analyze", "scan"):
        p = sub.add_parser(name)
        p.add_argument("repo", help="GitHub URL (https://github.com/org/repo), org/repo, or a local folder")
        p.add_argument("--branch", default=None, help="branch to check out (default: repo default branch)")
        p.add_argument("--ref", default=None, help="commit SHA or tag to check out")
        p.add_argument("--config", type=Path, default=None)
        p.add_argument("--output", type=Path, default=PROJECT_ROOT / "runs")
        p.add_argument("--continue-on-fail", action="store_true", help="run all stages even if a gate fails")
        p.add_argument("--skip", default="", help="comma list: tests,container")
        p.add_argument("--no-llm", action="store_true", help="force offline/deterministic mode")
        p.add_argument("-v", "--verbose", action="store_true")
    d = sub.add_parser("doctor")
    d.add_argument("--config", type=Path, default=None)
    c = sub.add_parser("clean", help="free disk space: delete old run folders and cached test environments")
    c.add_argument("--keep-runs", type=int, default=5, help="newest run folders to keep (default 5)")
    c.add_argument("--all-envs", action="store_true", help="also delete every cached test environment")
    c.add_argument("--config", type=Path, default=None)
    args = ap.parse_args(argv)

    setup_logging(getattr(args, "verbose", False))
    cfg = load_config(args.config)
    if args.cmd == "doctor":
        return doctor(cfg)
    if args.cmd == "clean":
        return clean(args.keep_runs, args.all_envs)
    if args.no_llm:
        cfg["llm"]["provider"] = "none"
    from cip.source.fetcher import is_remote
    if not is_remote(args.repo) and not Path(args.repo).is_dir():
        print(f"Repository not found: {args.repo} (give a local folder or a GitHub URL)", file=sys.stderr)
        return 2

    from cip.orchestrator.pipeline import Pipeline
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    if args.cmd in ("analyze", "scan"):
        skip |= {"tests", "container"}
    if args.cmd == "analyze":
        skip.add("security")
    pipe = Pipeline(args.repo, cfg, args.output, continue_on_fail=args.continue_on_fail, skip=skip,
                    branch=args.branch, ref=args.ref)
    state = pipe.run()
    return 0 if state["overall"] in ("PASS", "ANALYSIS ONLY") else 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.exit(main())
