"""CIP web UI – paste a GitHub URL, press Run, watch every step live.

    python -m cip.server            ->  http://127.0.0.1:8765  (opens your browser)
    python -m cip.server --port 9000 --no-browser

Endpoints
    GET  /                       single-page UI (cip/web/index.html)
    GET  /api/doctor             which tools / LLM / GitHub token are available
    POST /api/runs               start a run  {repo, branch?, ref?, continue_on_fail, run_tests, containerize, use_llm}
    GET  /api/runs               active + past runs
    GET  /api/runs/{run}/events  Server-Sent Events: every step / action / command / result / gate, live
    /runs/...                    the run folders (HTML report, pipeline.log, artifacts)
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import os
import threading
import time
import webbrowser
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cip import console as C
from cip.config import PROJECT_ROOT, load_config
from cip.utils import docker_available, find_tool

RUNS_DIR = PROJECT_ROOT / "runs"
WEB_DIR = Path(__file__).parent / "web"
TOOLS = ["git", "bandit", "semgrep", "pip-audit", "gitleaks", "ruff", "trivy", "docker"]

app = FastAPI(title="CIP – Code Intelligence Platform")
RUNS_DIR.mkdir(exist_ok=True)
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR), html=True), name="runs")


class RunRequest(BaseModel):
    repo: str
    branch: str | None = None
    ref: str | None = None
    continue_on_fail: bool = True
    run_tests: bool = True
    containerize: bool = True
    use_llm: bool = True


class LiveRun:
    """Events of one pipeline run, kept in memory for streaming and appended to events.jsonl for history."""

    def __init__(self, run: str, run_dir: Path):
        self.run = run
        self.run_dir = run_dir
        self.events: list[dict] = []
        self.done = False
        self.lock = threading.Lock()

    def add(self, event: dict) -> None:
        event = {"t": round(time.time(), 2), **event}
        with self.lock:
            self.events.append(event)
        try:
            with open(self.run_dir / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
        except OSError:
            pass
        if event["type"] == "done":
            self.done = True


class ThreadLogHandler(logging.Handler):
    """Forward module log lines (e.g. '[testing] Creating test virtualenv') of ONE run thread to the UI."""

    def __init__(self, live: LiveRun, thread_id: int):
        super().__init__(logging.INFO)
        self.live, self.thread_id = live, thread_id

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self.thread_id or record.name == "cip.flow":
            return
        level = "error" if record.levelno >= logging.ERROR else "warning" if record.levelno >= logging.WARNING else "info"
        self.live.add({"type": "log", "level": level, "source": record.name.removeprefix("cip."),
                       "text": record.getMessage()[:2000]})


ACTIVE: dict[str, LiveRun] = {}


def _worker(pipe, live: LiveRun) -> None:
    C.set_sink(live.add)
    handler = ThreadLogHandler(live, threading.get_ident())
    logging.getLogger().addHandler(handler)
    try:
        pipe.run()
    except Exception as e:  # pipeline already guards itself; this is a last resort
        live.add({"type": "done", "overall": "FAIL", "crash": str(e), "reports": {}})
    finally:
        logging.getLogger().removeHandler(handler)
        if not live.done:
            live.add({"type": "done", "overall": "FAIL", "crash": "run ended unexpectedly", "reports": {}})


# ------------------------------------------------------------------ API
@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/doctor")
def doctor():
    from cip.llm.client import LLMClient
    cfg = load_config()
    llm = LLMClient(cfg.get("llm", {}))
    return {
        "tools": {t: bool(find_tool(t)) for t in TOOLS},
        "docker_running": docker_available(),
        "llm": llm.describe(), "llm_enabled": llm.enabled, "llm_note": getattr(llm, "note", ""),
        "disk_free_gb": round(__import__("shutil").disk_usage(PROJECT_ROOT).free / 1e9, 1),
        "github_token": bool(os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")),
    }


@app.post("/api/runs")
def start_run(req: RunRequest):
    from cip.orchestrator.pipeline import Pipeline
    from cip.source.fetcher import is_remote
    repo = req.repo.strip()
    if not repo:
        raise HTTPException(400, "Enter a GitHub URL (https://github.com/org/repo), org/repo, or a local folder path")
    if not is_remote(repo) and not Path(repo).is_dir():
        raise HTTPException(400, f"Not a GitHub URL and no such local folder: {repo}")
    if any(not r.done for r in ACTIVE.values()):
        raise HTTPException(409, "A run is already in progress – wait for it to finish")
    cfg = load_config()
    if not req.use_llm:
        cfg["llm"]["provider"] = "none"
    skip = set()
    if not req.run_tests:
        skip.add("tests")
    if not req.containerize:
        skip.add("container")
    pipe = Pipeline(repo, copy.deepcopy(cfg), RUNS_DIR, continue_on_fail=req.continue_on_fail, skip=skip,
                    branch=(req.branch or "").strip() or None, ref=(req.ref or "").strip() or None)
    if pipe.run_dir.exists():                      # two runs in the same second
        time.sleep(1.1)
        pipe = Pipeline(repo, copy.deepcopy(cfg), RUNS_DIR, continue_on_fail=req.continue_on_fail, skip=skip,
                        branch=(req.branch or "").strip() or None, ref=(req.ref or "").strip() or None)
    pipe.run_dir.mkdir(parents=True, exist_ok=True)
    live = LiveRun(pipe.run_dir.name, pipe.run_dir)
    ACTIVE[live.run] = live
    threading.Thread(target=_worker, args=(pipe, live), daemon=True, name=f"cip-{live.run}").start()
    return {"run": live.run, "steps": pipe._steps}


@app.get("/api/runs")
def list_runs():
    out = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True) if RUNS_DIR.exists() else []:
        if not d.is_dir():
            continue
        item = {"run": d.name, "active": d.name in ACTIVE and not ACTIVE[d.name].done}
        rep = d / "assessment_report.json"
        if rep.exists():
            try:
                st = json.loads(rep.read_text(encoding="utf-8"))
                item.update(overall=st.get("overall"), source=st.get("source"), started_at=st.get("started_at"),
                            duration_s=st.get("duration_s"),
                            commit=(st.get("source_info") or {}).get("commit", "")[:10])
            except Exception:
                pass
        elif not item["active"]:
            continue
        item["has_events"] = (d / "events.jsonl").exists()
        out.append(item)
    return JSONResponse(out[:50])


@app.get("/api/runs/{run}/tests")
def run_tests(run: str):
    """Generated test files (code + how they were made) and the result of every test in the final pytest run."""
    import xml.etree.ElementTree as ET
    if "/" in run or "\\" in run or ".." in run:
        raise HTTPException(400, "bad run id")
    d = RUNS_DIR / run
    gen_meta = {}
    rep = d / "assessment_report.json"
    if rep.exists():
        st = json.loads(rep.read_text(encoding="utf-8"))
        for f in ((st.get("testing") or {}).get("generation") or {}).get("files", []):
            gen_meta[Path(f["file"]).stem] = f
    results: dict[str, list] = {}
    junit = d / "artifacts" / "tests" / "full.junit.xml"
    if junit.exists():
        for tc in ET.parse(junit).getroot().iter("testcase"):
            node = next((c for c in tc if c.tag in ("failure", "error", "skipped")), None)
            status = "passed" if node is None else ("xfail" if node.tag == "skipped" and "xfail" in
                                                    ((node.get("type") or "") + (node.get("message") or "")).lower()
                                                    else {"failure": "failed", "error": "error"}.get(node.tag, "skipped"))
            results.setdefault(tc.get("classname") or "", []).append(
                {"name": tc.get("name"), "status": status, "time": tc.get("time"),
                 "message": ((node.get("message") or "") if node is not None else "")[:500]})
    files = []
    gen_dir = d / "artifacts" / "generated_tests"
    for f in sorted(gen_dir.glob("test_*.py")) if gen_dir.exists() else []:
        meta = gen_meta.get(f.stem, {})
        files.append({"file": f.name, "module": meta.get("module"), "mode": meta.get("mode", "llm"),
                      "repairs": meta.get("attempts", 0), "status": meta.get("status"),
                      "stubbed_imports": meta.get("stubbed_imports", []),
                      "code": f.read_text(encoding="utf-8", errors="replace"),
                      "tests": next((v for k, v in results.items() if k.endswith(f.stem)), [])})
    generated = {f["file"][:-3] for f in files}
    others = [dict(t, suite=k) for k, v in results.items() if not any(k.endswith(g) for g in generated) for t in v]
    return {"generated": files, "existing_tests": others}


@app.get("/api/runs/{run}/events")
async def events(run: str):
    if "/" in run or "\\" in run or ".." in run:
        raise HTTPException(400, "bad run id")
    live = ACTIVE.get(run)
    if live is None:
        f = RUNS_DIR / run / "events.jsonl"
        if not f.exists():
            raise HTTPException(404, "no events recorded for this run (it was started from the terminal)")
        lines = f.read_text(encoding="utf-8").splitlines()

        async def replay():
            for i, line in enumerate(lines):
                yield f"id: {i}\ndata: {line}\n\n"
            yield "event: end\ndata: {}\n\n"
        return StreamingResponse(replay(), media_type="text/event-stream")

    async def stream():
        sent = 0
        idle = 0
        while True:
            with live.lock:
                batch = live.events[sent:]
            for ev in batch:
                yield f"id: {sent}\ndata: {json.dumps(ev, default=str)}\n\n"
                sent += 1
            if live.done and sent >= len(live.events):
                yield "event: end\ndata: {}\n\n"
                return
            idle = 0 if batch else idle + 1
            if idle and idle % 30 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)
    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main() -> None:
    ap = argparse.ArgumentParser(prog="cip.server", description="CIP web UI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    C.setup(False)
    load_config()  # loads .env
    url = f"http://{args.host}:{args.port}"
    print(f"\n  CIP web UI running at {url}   (Ctrl+C to stop)\n")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
