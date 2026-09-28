"""Human-readable, step-by-step terminal output (also written to runs/<run>/pipeline.log).

    23:40:01 │ ══════════════════════════════════════════════════════════════════════
    23:40:01 │  STEP 3/8 · CODE SCANNING
    23:40:01 │  Static analysis, dependency CVEs, secrets, lint and config checks
    23:40:01 │ ──────────────────────────────────────────────────────────────────────
    23:40:01 │   → bandit  (Python SAST: insecure code patterns)
    23:40:01 │       $ bandit -r <repo> -f json -q ...
    23:40:02 │   ✔ bandit: 13 findings  HIGH 5 · MEDIUM 6 · LOW 2   (0.4s)
    23:40:02 │       · [cip.testing] messages from inside a module look like this
"""
from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

flow = logging.getLogger("cip.flow")
_sink = threading.local()   # per-thread event listener (the web UI runs each pipeline in its own thread)


def set_sink(fn) -> None:
    """Register a callable that receives every structured event emitted on this thread."""
    _sink.fn = fn


def emit(event: dict) -> None:
    fn = getattr(_sink, "fn", None)
    if fn:
        try:
            fn(event)
        except Exception:  # the UI must never break the pipeline
            pass
WIDTH = 74
ICONS = {"passed": "✔", "ok": "✔", "findings": "●", "failed": "✘", "error": "✘", "skipped": "–",
         "warning": "!", "info": "•"}


class FlowFormatter(logging.Formatter):
    """cip.flow lines are the storyline; everything else is shown indented underneath."""

    def format(self, record: logging.LogRecord) -> str:
        t = self.formatTime(record, "%H:%M:%S")
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        if record.name == "cip.flow":
            prefix = ""
        elif record.levelno >= logging.ERROR:
            prefix = "      ✘ "
        elif record.levelno >= logging.WARNING:
            prefix = "      ⚠ "
        else:
            prefix = f"      · [{record.name.removeprefix('cip.')}] "
        lines = msg.splitlines() or [""]
        return "\n".join(f"{t} │ {prefix if i == 0 else ' ' * len(prefix)}{line}" for i, line in enumerate(lines))


def setup(verbose: bool = False) -> None:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles: never crash on ✔ / box characters
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(FlowFormatter())
    root.addHandler(h)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for noisy in ("httpx", "httpcore", "urllib3", "anthropic", "openai", "httpx2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def add_run_log(path: Path) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(FlowFormatter())
    logging.getLogger().addHandler(fh)
    return fh


# ---------------------------------------------------------------- storyline helpers
def banner(n: int, total: int, title: str, purpose: str) -> None:
    emit({"type": "step", "n": n, "total": total, "title": title, "purpose": purpose})
    flow.info("")
    flow.info("═" * WIDTH)
    flow.info(f" STEP {n}/{total} · {title}")
    flow.info(f" {purpose}")
    flow.info("─" * WIDTH)


def action(msg: str) -> None:
    emit({"type": "action", "text": msg})
    flow.info(f"  → {msg}")


def command(cmd: str) -> None:
    if cmd:
        emit({"type": "command", "text": cmd})
        flow.info(f"      $ {cmd if len(cmd) <= 150 else cmd[:147] + '...'}")


def detail(msg: str) -> None:
    emit({"type": "detail", "text": str(msg)})
    for line in str(msg).splitlines():
        flow.info(f"      {line}")


def result(status: str, msg: str) -> None:
    emit({"type": "result", "status": status, "text": msg})
    flow.info(f"  {ICONS.get(status, '•')} {msg}")


def sev_line(counts: dict) -> str:
    parts = [f"{k} {v}" for k, v in counts.items() if v]
    return " · ".join(parts) if parts else "none"


def title(text: str) -> None:
    emit({"type": "title", "text": text})
    flow.info("")
    flow.info("█" * WIDTH)
    flow.info(f" {text}")
    flow.info("█" * WIDTH)


def table(rows: list[list[str]], headers: list[str]) -> None:
    widths = [max(len(str(r[i])) for r in rows + [headers]) for i in range(len(headers))]
    fmt = "   " + "  ".join(f"{{:<{w}}}" for w in widths)
    flow.info(fmt.format(*headers))
    flow.info("   " + "  ".join("-" * w for w in widths))
    for r in rows:
        flow.info(fmt.format(*[str(c) for c in r]))
