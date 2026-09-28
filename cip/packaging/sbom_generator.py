"""CycloneDX SBOM via Trivy (filesystem, and image when available)."""
from __future__ import annotations

from pathlib import Path

from cip.security.trivy_scanner import run_trivy


def generate_sbom(target: str, out_file: Path, repo: Path, kind: str = "fs") -> dict:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    args = [kind, "--format", "cyclonedx", "--quiet", target if kind == "image" else "{src}"]
    res = run_trivy(args, repo)
    if res.skipped:
        return {"status": "skipped", "message": res.skip_reason}
    if not res.ok or not res.stdout.strip().startswith("{"):
        return {"status": "error", "message": (res.stderr or res.stdout)[-400:]}
    out_file.write_text(res.stdout, encoding="utf-8")
    import json
    comps = len(json.loads(res.stdout).get("components", []) or [])
    return {"status": "ok", "file": out_file.name, "components": comps}
