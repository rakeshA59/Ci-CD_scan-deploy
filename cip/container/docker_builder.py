"""docker build + a short runtime smoke check of the built image."""
from __future__ import annotations

import time
from pathlib import Path

from cip.utils import run_cmd


def build_image(workspace: Path, image: str, log_file: Path) -> dict:
    res = run_cmd(["docker", "build", "-t", image, "-f", str(workspace / "Dockerfile"), str(workspace)],
                  timeout=2400)
    log_file.write_text(res.stdout + "\n" + res.stderr, encoding="utf-8")
    if not res.ok:
        return {"image_built": False, "message": f"docker build failed: {(res.stderr or res.stdout)[-1200:]}"}
    size = run_cmd(["docker", "image", "inspect", image, "--format", "{{.Size}}"]).stdout.strip()
    digest = run_cmd(["docker", "image", "inspect", image, "--format", "{{.Id}}"]).stdout.strip()
    return {"image_built": True, "image": image, "image_id": digest,
            "size_mb": round(int(size) / 1e6, 1) if size.isdigit() else None}


def remove_old_images(image: str) -> list[str]:
    """Delete earlier images CIP built for the same repo (each is ~1 GB); keep the one just built."""
    repo = image.split(":")[0]
    tags = run_cmd(["docker", "images", repo, "--format", "{{.Repository}}:{{.Tag}}"]).stdout.split()
    old = [t for t in tags if t != image and not t.endswith(":<none>")]
    for t in old:
        run_cmd(["docker", "rmi", "-f", t])
    return old


def smoke_run(image: str, port: int, env: dict, wait_s: int = 12, probe_path: str | None = "/docs") -> dict:
    """Start the container, check it stays up (and answers HTTP if it exposes a port), then remove it."""
    name = f"cip-smoke-{int(time.time())}"
    cmd = ["docker", "run", "-d", "--name", name]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    if port:
        cmd += ["-p", f"127.0.0.1::{port}"]
    start = run_cmd(cmd + [image], timeout=120)
    if not start.ok:
        return {"status": "failed", "message": start.stderr[-500:]}
    time.sleep(wait_s)
    running = run_cmd(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip() == "true"
    http = None
    if running and port and probe_path:
        probe = run_cmd(["docker", "exec", name, "python", "-c",
                         f"import urllib.request as u\ntry:\n  r=u.urlopen('http://127.0.0.1:{port}{probe_path}',timeout=5);print(r.status)\n"
                         f"except Exception as e:\n  print(getattr(e,'code','ERR'))"], timeout=30)
        http = probe.stdout.strip()
    out = run_cmd(["docker", "logs", "--tail", "40", name])
    logs = out.stdout + out.stderr
    run_cmd(["docker", "rm", "-f", name])
    ok = running and (http is None or (http.isdigit() and int(http) < 500))
    return {"status": "passed" if ok else "failed", "running_after_s": wait_s if running else 0,
            "http_probe": http, "logs_tail": logs[-2000:]}
