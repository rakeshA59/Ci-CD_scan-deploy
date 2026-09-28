"""Stage 0 – get the code: clone a GitHub (or any git) repository, or copy a local folder.

Accepted sources
    https://github.com/org/repo(.git)     public or private (GITHUB_TOKEN)
    git@github.com:org/repo.git           uses your SSH keys
    org/repo                              shorthand for https://github.com/org/repo
    C:\\path\\to\\local\\repo                 copied (never modified)

Private repos: put a GitHub token in .env as GITHUB_TOKEN (fine-grained, "Contents: read-only").
The token is sent as an HTTP header only – it is never written into the clone's git config, the
report, or the logs.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import shutil
import urllib.request
import zipfile
from pathlib import Path

from cip.utils import IGNORED_DIRS, find_tool, run_cmd

log = logging.getLogger("cip.source")
_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB = re.compile(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$")


def is_remote(source: str) -> bool:
    if source.startswith(("https://", "http://", "git@", "ssh://")):
        return True
    return bool(_SHORTHAND.match(source)) and not Path(source).exists()


def normalise_url(source: str) -> str:
    if _SHORTHAND.match(source) and not source.startswith(("http", "git@")):
        return f"https://github.com/{source}.git"
    return source


def repo_name(source: str) -> str:
    m = _GITHUB.search(source)
    if m:
        return m.group(2)
    return Path(source.rstrip("/\\")).name.removesuffix(".git") or "repo"


def _redact(text: str) -> str:
    return re.sub(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|x-access-token:[^@\s]+)", "***", text or "")


def _git(args: list[str], cwd: Path | None = None, token: str | None = None, timeout: int = 900):
    git = find_tool("git")
    cmd = [git]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraHeader=Authorization: Basic {basic}"]
    res = run_cmd(cmd + args, cwd=cwd, timeout=timeout, env={"GIT_TERMINAL_PROMPT": "0"})
    res.cmd = ["git"] + args  # never keep the header in logs/report
    res.stderr = _redact(res.stderr)
    return res


def fetch_source(source: str, dest: Path, branch: str | None = None, ref: str | None = None) -> dict:
    """Populate `dest` with the code. Returns provenance info for the report."""
    if not is_remote(source):
        src = Path(source).resolve()
        if not src.is_dir():
            raise FileNotFoundError(f"Source folder not found: {src}")
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns(*IGNORED_DIRS, "*.pyc", "*.egg-info"))
        info = {"type": "local", "path": str(src)}
        if (src / ".git").exists() and find_tool("git"):
            info.update(_git_meta(src))
        return info

    url = normalise_url(source)
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    use_token = token if "github.com" in url and url.startswith("http") else None
    if find_tool("git"):
        return _clone(url, dest, branch, ref, use_token)
    log.warning("git not installed – downloading a GitHub archive instead (no git metadata)")
    return _download_zip(url, dest, branch or ref, token)


def _clone(url: str, dest: Path, branch: str | None, ref: str | None, token: str | None) -> dict:
    log.info("Cloning %s%s%s", url, f" (branch {branch})" if branch else "", f" @ {ref}" if ref else "")
    args = ["clone", "--quiet", "--no-tags"]
    if not ref:
        args += ["--depth", "1"]          # latest commit is enough for scanning
    if branch:
        args += ["--branch", branch, "--single-branch"]
    res = _git(args + [url, str(dest)], token=token, timeout=1800)
    if not res.ok:
        hint = ""
        if "Authentication failed" in res.stderr or "could not read Username" in res.stderr or "not found" in res.stderr.lower():
            hint = " | HINT: private repo? set GITHUB_TOKEN in .env (a token with read access to Contents)."
        raise RuntimeError(f"git clone failed: {res.stderr.strip()[-600:]}{hint}")
    if ref:
        co = _git(["checkout", "--quiet", ref], cwd=dest)
        if not co.ok:
            raise RuntimeError(f"git checkout {ref} failed: {co.stderr.strip()[-400:]}")
    info = {"type": "git", "url": _redact(url), "requested_branch": branch, "requested_ref": ref}
    info.update(_git_meta(dest))
    return info


def _git_meta(repo: Path) -> dict:
    def q(*a):
        r = _git(list(a), cwd=repo)
        return r.stdout.strip() if r.ok else ""
    return {
        "commit": q("rev-parse", "HEAD"),
        "branch": q("rev-parse", "--abbrev-ref", "HEAD"),
        "commit_author": q("log", "-1", "--format=%an"),
        "commit_date": q("log", "-1", "--format=%cI"),
        "commit_message": q("log", "-1", "--format=%s")[:200],
        "remote": _redact(q("config", "--get", "remote.origin.url")),
    }


def _download_zip(url: str, dest: Path, ref: str | None, token: str | None) -> dict:
    m = _GITHUB.search(url)
    if not m:
        raise RuntimeError("git is not installed and the source is not a GitHub URL – install Git for Windows")
    owner, repo = m.group(1), m.group(2)
    api = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    req = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json", "User-Agent": "cip"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = resp.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        top = zf.namelist()[0].split("/")[0]
        zf.extractall(dest.parent / "_zip")
    shutil.move(str(dest.parent / "_zip" / top), dest)
    shutil.rmtree(dest.parent / "_zip", ignore_errors=True)
    commit = top.rsplit("-", 1)[-1]
    return {"type": "github-archive", "url": f"https://github.com/{owner}/{repo}", "requested_ref": ref,
            "commit": commit}


def describe(info: dict) -> str:
    if info.get("type") == "local":
        return info["path"] + (f" @ {info['commit'][:10]}" if info.get("commit") else "")
    return f"{info.get('url')} [{info.get('branch') or info.get('requested_ref') or 'default'}] @ {(info.get('commit') or '')[:10]}"
