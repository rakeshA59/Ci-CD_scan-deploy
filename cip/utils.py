"""Shared helpers: running external tools (cross-platform), logging, file walking."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("cip")

# Directories we never analyse or scan.
IGNORED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".env", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules", "build", "dist",
    ".idea", ".vscode", "site-packages", ".pixi", ".eggs", "htmlcov", ".cip",
}


@dataclass
class CmdResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False
    skip_reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.skipped and self.returncode == 0


def find_tool(name: str) -> Optional[str]:
    """Locate an executable on PATH, also checking the current interpreter's Scripts/bin dir
    (important on Windows where pip installs console scripts next to python.exe)."""
    found = shutil.which(name)
    if found:
        return found
    scripts = Path(sys.executable).parent
    for cand in (scripts / name, scripts / f"{name}.exe", scripts / "Scripts" / f"{name}.exe"):
        if cand.exists():
            return str(cand)
    return None


def docker_available() -> bool:
    docker = find_tool("docker")
    if not docker:
        return False
    try:
        r = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def run_cmd(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 900,
            env: Optional[dict] = None) -> CmdResult:
    log.debug("RUN %s (cwd=%s)", " ".join(cmd), cwd)
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, **(env or {})}, encoding="utf-8", errors="replace",
        )
        return CmdResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError as e:
        return CmdResult(cmd, 127, "", str(e), skipped=True, skip_reason=f"not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return CmdResult(cmd, 124, "", f"timeout after {timeout}s", skipped=True,
                         skip_reason=f"timeout after {timeout}s")


def run_tool(tool: str, args: list[str], repo: Path, docker_image: Optional[str] = None,
             docker_args: Optional[list[str]] = None, timeout: int = 900,
             prefer_docker: bool = False) -> CmdResult:
    """Run a scanner natively if installed, otherwise fall back to its Docker image.

    `args` must reference the repo as the placeholder "{src}" – it is replaced by the local
    path natively, or by /src inside the container.
    """
    native = find_tool(tool)
    use_docker = docker_image and (prefer_docker or not native) and docker_available()
    if native and not use_docker:
        return run_cmd([native] + [a.replace("{src}", str(repo)) for a in args], cwd=repo, timeout=timeout)
    if use_docker:
        dargs = docker_args if docker_args is not None else args
        cmd = ["docker", "run", "--rm", "-v", f"{repo.resolve()}:/src", "-w", "/src", docker_image]
        cmd += [a.replace("{src}", "/src") for a in dargs]
        return run_cmd(cmd, timeout=timeout)
    return CmdResult([tool] + args, 127, "", "", skipped=True,
                     skip_reason=f"'{tool}' not installed and Docker unavailable")


def parse_json(text: str, default=None):
    text = (text or "").strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools print banners before JSON; try from first brace/bracket.
        for opener in ("{", "["):
            idx = text.find(opener)
            if idx != -1:
                try:
                    return json.loads(text[idx:])
                except json.JSONDecodeError:
                    continue
    return default


def iter_files(root: Path, suffixes: Optional[Iterable[str]] = None) -> Iterable[Path]:
    suffixes = set(suffixes) if suffixes else None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.endswith(".egg-info")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if suffixes is None or p.suffix in suffixes:
                yield p


def read_text(path: Path, limit: Optional[int] = None) -> str:
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return txt[:limit] if limit else txt


def rel(path: Path | str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path).replace("\\", "/")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
