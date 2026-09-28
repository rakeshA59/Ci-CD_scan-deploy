from __future__ import annotations

from pathlib import Path

from cip.security.base import Finding, ScanResult, Scanner, norm_severity
from cip.utils import CmdResult, parse_json, run_cmd, find_tool, docker_available

TRIVY_IMAGE = "aquasec/trivy:latest"


def trivy_error(stderr: str) -> str:
    """Turn Trivy's FATAL log line into a readable message + hint."""
    text = (stderr or "").strip()
    if "not enough space on the disk" in text or "no space left on device" in text.lower():
        return ("Disk full: Trivy copies the image to your TEMP folder to scan it and the drive ran out of space. "
                "Free a few GB (python -m cip.cli clean, docker system prune) and rerun.")
    if "failed to download vulnerability DB" in text or "DB error" in text:
        return ("Trivy could not download its vulnerability database (first run needs internet access to "
                "ghcr.io / mirror.gcr.io; behind a proxy set HTTPS_PROXY). Raw: " + text[-200:])
    if "Cannot connect to the Docker daemon" in text or "unable to inspect the image" in text:
        return "Trivy could not reach Docker to read the image – is Docker Desktop running?"
    return text[-500:]


def parse_trivy(data: dict, scanner: str, category_vuln: str) -> list[Finding]:
    findings = []
    for result in (data or {}).get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                scanner=scanner, category=category_vuln, severity=norm_severity(v.get("Severity")),
                title=f"{v.get('PkgName')} {v.get('InstalledVersion')} – {v.get('VulnerabilityID')}"
                      + (f": {v.get('Title')}" if v.get("Title") else ""),
                file=target, rule_id=v.get("VulnerabilityID", ""),
                cve=v.get("VulnerabilityID", ""), package=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""), fixed_version=v.get("FixedVersion", "") or "",
                cwe=(v.get("CweIDs") or [""])[0], description=(v.get("Description") or "")[:600],
                recommendation=f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}" if v.get("FixedVersion")
                else "No fix available yet – consider alternative package / base image",
                references=[v["PrimaryURL"]] if v.get("PrimaryURL") else [], confidence="HIGH",
            ))
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            findings.append(Finding(
                scanner=scanner, category="misconfiguration", severity=norm_severity(m.get("Severity")),
                title=f"{m.get('ID')}: {m.get('Title')}", file=target,
                line=int(((m.get("CauseMetadata") or {}).get("StartLine")) or 0),
                rule_id=m.get("ID", ""), description=m.get("Message") or m.get("Description", ""),
                recommendation=m.get("Resolution", ""), references=(m.get("References") or [])[:2],
            ))
    return findings


def run_trivy(args: list[str], repo: Path, timeout: int = 1500) -> CmdResult:
    """Run trivy natively or via docker (with docker socket mounted for image scans)."""
    if find_tool("trivy"):
        return run_cmd([find_tool("trivy")] + [a.replace("{src}", str(repo)) for a in args], timeout=timeout)
    if docker_available():
        cmd = ["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
               "-v", f"{repo.resolve()}:/src", "-v", "cip-trivy-cache:/root/.cache/", TRIVY_IMAGE]
        return run_cmd(cmd + [a.replace("{src}", "/src") for a in args], timeout=timeout)
    return CmdResult(["trivy"] + args, 127, "", "", skipped=True, skip_reason="trivy not installed and Docker unavailable")


class TrivyFsScanner(Scanner):
    """Filesystem scan: dependency vulns (with severities) + Dockerfile/IaC misconfigurations."""
    name = "trivy-fs"

    def _scan(self, repo: Path) -> ScanResult:
        res = run_trivy(["fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet",
                         "--skip-dirs", "**/.venv", "--skip-dirs", "**/node_modules", "{src}"], repo)
        if res.skipped:
            return self._skipped(res)
        data = parse_json(res.stdout, None)
        raw = self._save_raw(res)
        if data is None:
            return ScanResult(self.name, "error", message=trivy_error(res.stderr), command=" ".join(res.cmd), raw_output=raw)
        return ScanResult(self.name, findings=parse_trivy(data, self.name, "dependency"),
                          command=" ".join(res.cmd), raw_output=raw)
