# Code Intelligence Platform (CIP) – V1 POC

AI-assisted source-code assessment and deployment pipeline for **Python** repositories.

```
GitHub repo / local folder → checkout (git clone, commit SHA recorded)
       → Deterministic analysis (files / deps / AST) → LLM understanding
       → Security toolchain (Bandit, Semgrep, pip-audit, Gitleaks, Ruff, Trivy) → LLM triage → SECURITY GATE
       → Test generation (LLM) → pytest + coverage → TEST GATE
       → Package + SBOM → Dockerfile (generate/lint) → docker build → smoke run → Trivy image scan → CONTAINER GATE
       → Assessment report (HTML / Markdown / JSON) + artifacts
```

**Scanners detect, the LLM explains, deterministic gates decide.** The LLM never changes severities or
pass/fail. Without an API key everything still runs in offline mode (heuristic summary, rule-based triage,
smoke tests).

The source repo is **never modified** – each run clones (or copies) it into `runs/<repo>-<timestamp>/workspace`,
and the report records the exact commit that was assessed.

## Quick start (Windows)

```bat
cd C:\Users\AnjanaG\Desktop\Ci-CD_scan-deploy
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env        &REM add ANTHROPIC_API_KEY (or OpenAI / Azure) – optional

python -m cip.cli doctor                                     &REM tools + a live LLM test call
python -m cip.cli run sample_apps\customer_api --continue-on-fail
python -m cip.cli run https://github.com/org/repo                    &REM clone from GitHub
python -m cip.cli run org/repo --branch develop                      &REM shorthand + branch
python -m cip.cli run org/repo --ref 3f2a9c1                         &REM exact commit / tag
python -m cip.cli run C:\path\to\your\repo                           &REM local folder
```

**Private GitHub repos:** add `GITHUB_TOKEN=` to `.env` (fine-grained token, *Contents: Read-only*). It is
sent only as an HTTP header – never stored in the clone, report or logs. Requires Git for Windows
(`winget install Git.Git`); without git, CIP downloads the GitHub zip archive instead.

Or just `run.bat sample_apps\customer_api --continue-on-fail` (creates `.venv` on first use).

Open `runs\<repo>-<timestamp>\assessment_report.html` in a browser.

The terminal shows the run as numbered steps (`STEP 1/8 · CHECKOUT` … `STEP 8/8 · REPORT`): for every step
what it does, the exact command it runs, the result, and each gate check. The same log is saved as
`runs\<repo>-<timestamp>\pipeline.log`.

### Web UI (recommended)

```bat
python -m cip.server          &REM or double-click ui.bat  ->  http://127.0.0.1:8765 opens in your browser
```

Paste a GitHub URL (or `org/repo`, or a local folder), choose options, press **Run pipeline**. The left panel shows
the 8 steps turning green/red live; click any step to see exactly what it did – actions, the commands it ran (with a
copy button), results, and gate checks. When the run ends you get result cards (security, tests, container, package)
and links to the full HTML report and `pipeline.log`. **Recent runs** lets you replay any earlier run step by step.
Only one run at a time; the server listens on 127.0.0.1 only. Use `--port` to change the port.

### Commands

| Command | What it does |
|---|---|
| `python -m cip.cli analyze <repo>` | Phase 1 only – tech stack / architecture discovery |
| `python -m cip.cli scan <repo>` | Discovery + security scanners + triage + security gate |
| `python -m cip.cli run <repo>` | Full pipeline |
| `python -m cip.cli doctor` | Show installed tools, Docker, LLM status (makes one tiny live LLM call), GitHub token |

Flags: `--continue-on-fail` (run all stages even when a gate fails – useful for a POC), `--skip tests,container`,
`--no-llm`, `--config other.yaml`, `-v`.

Overall result: **PASS** (all gates passed), **FAIL** (a gate failed or a stage broke), **INCOMPLETE** (nothing
failed but a stage could not run, e.g. no Docker), **ANALYSIS ONLY** (`analyze`). Exit code is `0` only for PASS, so it can be dropped straight into a CI job.

## External tools

| Tool | Install on Windows | If missing |
|---|---|---|
| bandit, pip-audit, ruff, semgrep | `pip install -r requirements.txt` | semgrep → Docker image `semgrep/semgrep` |
| gitleaks | `winget install gitleaks` or `choco install gitleaks` | Docker image `zricethezav/gitleaks` |
| trivy | `winget install AquaSecurity.Trivy` or `choco install trivy` | Docker image `aquasec/trivy` |
| Docker Desktop | docker.com | container stage is skipped (Dockerfile still produced) |

Anything that can't run is shown as *skipped* in the report; the security gate can be made strict with
`fail_on_skipped_scanner: true`. The container gate fails if the image could not be scanned (`require_image_scan`).

## Configuration – `config/pipeline.yaml`

- `llm` – provider/model (`${ENV:-default}` substitution from `.env`)
- `security.scanners` – toggle each scanner; `semgrep_configs` registry rulesets (+ bundled `config/semgrep_rules.yml`)
- `quality_gate` – thresholds (critical/high/secrets, pass rate, coverage, container vulns, Dockerfile issues)
- `testing` – venv isolation (cached per requirements hash in `.cip/venvs`), modules to generate for, repair attempts
- `container` – generate Dockerfile if missing, base image, image name

## How test generation works

1. `testing/test_analyzer.py` ranks modules (public functions, routes, complexity, no existing tests) and lists scenarios.
2. The LLM writes a hermetic pytest file per module (mocks DB/HTTP/LLM, FastAPI `TestClient` + `dependency_overrides`).
3. Each file is **executed**; failures go back to the LLM for repair (`max_repair_attempts`).
4. Tests that still fail are pruned; files that can't even be collected are quarantined. Both are listed in the report.
5. Where the LLM concludes the *application* is wrong, the test is kept as `xfail` and surfaced as a **suspected defect**.
6. Full suite (existing + generated) runs with coverage → test gate. Generated tests are exported to `artifacts/generated_tests`.

## Output (`runs/<repo>-<timestamp>/`)

```
assessment_report.html / .md / .json
pipeline.log               step-by-step terminal output
events.jsonl               the same steps as structured events (UI replay)
artifacts/
  evidence.json               deterministic analysis
  application_analysis.json   LLM (or heuristic) understanding
  security_report.json        unified findings (common schema) + triage
  raw/                        raw scanner outputs
  tests/                      junit xml, coverage.json, htmlcov/, per-file logs, quarantine/
  generated_tests/            generated pytest files
  dist/                       wheel+sdist (libraries) or source bundle (applications)
  sbom.cdx.json, sbom-image.cdx.json   CycloneDX SBOMs
  Dockerfile, docker_build.log
workspace/                    the copy that was analysed/tested/built
```

## Sample target

`sample_apps/customer_api` is a small FastAPI + MongoDB + JWT service with **deliberate** vulnerabilities
(eval injection, `shell=True`, pickle, unsafe YAML, hard-coded JWT secret and token, MD5, `verify=False`,
wildcard CORS, outdated deps). Expected result: security gate FAIL with those issues listed and triaged.

## Layout

```
cip/
  source/        fetcher (git clone / GitHub archive / local copy)
  analyzer/      repository_scanner, language_detector, dependency_analyzer, ast_analyzer, llm_analyzer
  security/      bandit, semgrep, pip-audit (dependency), gitleaks (secret), ruff (quality), trivy fs, normalizer, triage
  testing/       test_analyzer, test_generator, test_runner (venv + pytest + coverage)
  quality/       quality_gate
  packaging/     python_packager, sbom_generator
  container/     dockerfile_generator (+ lint), docker_builder (+ smoke run), container_scanner
  llm/           client (Anthropic / OpenAI / Azure OpenAI), context_builder, prompts/*.md
  report/        report_builder
  orchestrator/  pipeline
  cli.py
```

## Next steps (after V1)

LangGraph supervisor over these modules, GitHub/GitLab ingestion, CI templates, dashboard & approval workflow,
auto-fix PRs from triage `fixed_code`, Java/Node analyzers (plug into `language_detector.SUPPORTED_LANGUAGES`).
