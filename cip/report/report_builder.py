"""Final assessment report: JSON (machine), Markdown (PR/CI comment) and self-contained HTML."""
from __future__ import annotations

import html
import json
from pathlib import Path

from cip.utils import write_json

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _gate_word(state: dict, gate: str) -> str:
    g = state.get("gates", {}).get(gate)
    if not g:
        return "NOT RUN"
    if g.get("skipped"):
        return "SKIPPED"
    return "PASS" if g["passed"] else "FAIL"


def _sec_status(state: dict, category: str) -> str:
    sec = state.get("security")
    if not sec:
        return "NOT RUN"
    fs = [f for f in sec["findings"] if f["category"] == category and f["severity"] in ("CRITICAL", "HIGH")]
    n = sum(1 for f in sec["findings"] if f["category"] == category)
    return f"{'FAIL' if fs else 'PASS'} ({n} findings, {len(fs)} critical/high)"


def render_text(state: dict) -> str:
    app = state.get("application", {})
    t = state.get("testing", {})
    c = state.get("container", {})
    gen = t.get("generation", {}) or {}
    csev = (c.get("scan") or {}).get("by_severity", {})
    lines = [
        "=" * 56, "            APPLICATION ASSESSMENT REPORT", "=" * 56, "",
        f"Run:             {state['run_id']}", f"Source:          {state['source']}",
        *( [f"Commit:          {si.get('commit', '')[:12]} ({si.get('branch') or '-'}) {si.get('commit_message', '')}"]
           if (si := state.get("source_info") or {}).get("commit") else []),
        f"LLM:             {state['llm']}", "",
        "APPLICATION", "-" * 11,
        f"Name:            {app.get('application_name', '-')}",
        f"Type:            {app.get('application_type', '-')}",
        f"Language:        {app.get('language', '-')}",
        f"Framework:       {', '.join(app.get('frameworks') or []) or '-'}",
        f"Database:        {', '.join(app.get('databases') or []) or '-'}",
        f"Authentication:  {app.get('authentication', '-')}",
        f"Architecture:    {app.get('architecture_style', '-')}", "",
        "SECURITY", "-" * 8,
        f"SAST:            {_sec_status(state, 'sast')}",
        f"Dependencies:    {_sec_status(state, 'dependency')}",
        f"Secrets:         {_sec_status(state, 'secret')}",
        f"Misconfig:       {_sec_status(state, 'misconfiguration')}",
        "Container:       " + (f"C{csev.get('CRITICAL', 0)} H{csev.get('HIGH', 0)} M{csev.get('MEDIUM', 0)} L{csev.get('LOW', 0)}" if csev else "NOT RUN"),
        "", "TESTING", "-" * 7,
        f"Tests:           {t.get('passed', 0)}/{t.get('total', 0)} passed" + (f", {t.get('xfailed')} xfail (suspected defects)" if t.get("xfailed") else "") if t else "Tests:           NOT RUN",
        f"Coverage:        {t.get('coverage_percent')}%" if t else "",
        f"Generated:       {gen.get('generated_ok', 0)} test files ({gen.get('mode', '-')}), {len(gen.get('quarantined', []))} quarantined" if gen else "",
        "", "QUALITY GATES", "-" * 13,
        f"Security gate:   {_gate_word(state, 'security')}",
        f"Test gate:       {_gate_word(state, 'testing')}",
        f"Container gate:  {_gate_word(state, 'container')}",
        f"OVERALL:         {state.get('overall')}", "",
        "ARTIFACTS", "-" * 9,
    ] + [f"✓ {a['kind']}: {a['path']}" for a in state.get("artifacts", [])]
    return "\n".join(l for l in lines if l is not None)


def render_markdown(state: dict) -> str:
    md = ["# Application Assessment Report", "", "```text", render_text(state), "```", ""]
    sec = state.get("security")
    if sec:
        tri = sec.get("triage", {})
        md += ["## Security triage", "", tri.get("executive_summary", ""), ""]
        if tri.get("top_priorities"):
            md += ["**Fix first:**", ""] + [f"1. {p}" for p in tri["top_priorities"]] + [""]
        if tri.get("correlations"):
            md += ["**Correlations:**", ""] + [f"- {c}" for c in tri["correlations"]] + [""]
        md += ["| ID | Sev | Category | Scanner | Location | Finding | Remediation |", "|---|---|---|---|---|---|---|"]
        for f in sec["findings"]:
            if f["category"] == "code_quality":
                continue
            rem = (f.get("triage") or {}).get("remediation") or f.get("recommendation", "")
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            md.append(f"| {f['id']} | {f['severity']} | {f['category']} | {f['scanner']}"
                      f"{'+' + '+'.join(f['also_reported_by']) if f['also_reported_by'] and f['category'] != 'dependency' else ''} "
                      f"| `{loc}` | {f['title'][:90]} | {rem[:160].replace('|', '/')} |")
        cq = [f for f in sec["findings"] if f["category"] == "code_quality"]
        md += ["", f"Code quality (Ruff): {len(cq)} findings – see security_report.json", ""]
    gen = (state.get("testing") or {}).get("generation") or {}
    if gen.get("suspected_defects"):
        md += ["## Suspected defects found by generated tests", ""] + [f"- `{d['module']}`: {d['defect']}" for d in gen["suspected_defects"]] + [""]
    md += ["## Stages", "", "| Stage | Status | Time | Detail |", "|---|---|---|---|"]
    md += [f"| {s['stage']} | {s['status']} | {s['duration_s']}s | {str(s.get('message', ''))[:120].replace('|', '/')} |" for s in state["stages"]]
    return "\n".join(md) + "\n"


# ----------------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;--pass:#1f7a4d;--fail:#b3261e;--warn:#9a6700;
--crit:#7a0b12;--high:#c0392b;--med:#b7791f;--low:#3a6ea5;--info:#6b6b66;--code:#f0efe9}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--card:#1f1f1d;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f;
--pass:#4cc38a;--fail:#ff6b61;--warn:#e3b341;--crit:#ff8a8a;--high:#ff7b6b;--med:#e3b341;--low:#7aa7e0;--code:#2a2a27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.v{font-size:20px;font-weight:600;margin-top:2px}
.PASS,.passed{color:var(--pass)}.FAIL,.failed{color:var(--fail)}.warning,.skipped,.SKIPPED,.INCOMPLETE{color:var(--warn)}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}.INFO{color:var(--info)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted);font-weight:600}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--code);border-radius:6px}code{padding:1px 4px}
pre{padding:10px;overflow-x:auto;white-space:pre-wrap;margin:6px 0 0}details summary{cursor:pointer}.wrap{overflow-x:auto}
.overall{font-size:28px;font-weight:700}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def render_html(state: dict) -> str:
    app = state.get("application", {})
    sec = state.get("security") or {}
    t = state.get("testing") or {}
    c = state.get("container") or {}
    sev = (sec.get("summary") or {}).get("by_severity", {})
    tri = sec.get("triage", {})
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>Assessment {_e(app.get('application_name', ''))}</title><style>{CSS}</style></head><body><main>",
             f"<h1>Application Assessment – {_e(app.get('application_name', state['source']))}</h1>",
             f"<div class=muted>Run {_e(state['run_id'])} · {_e(state['source'])}"
             + (f" · commit <code>{_e((state.get('source_info') or {}).get('commit', '')[:12])}</code> ({_e((state.get('source_info') or {}).get('branch'))})" if (state.get('source_info') or {}).get('commit') else "")
             + f" · LLM: {_e(state['llm'])} · {state.get('duration_s')}s</div>",
             "<h2>Result</h2><div class=grid>",
             f"<div class=card><div class=k>Overall</div><div class='overall {_e(state.get('overall'))}'>{_e(state.get('overall'))}</div></div>"]
    for g in ("security", "testing", "container"):
        w = _gate_word(state, g)
        parts.append(f"<div class=card><div class=k>{g} gate</div><div class='v {w.split()[0]}'>{w}</div></div>")
    parts.append("</div>")

    # application
    parts.append("<h2>Application</h2><div class=card><p>" + _e(app.get("purpose", "")) + "</p><div class=grid>")
    for label, key in (("Type", "application_type"), ("Language", "language"), ("Frameworks", "frameworks"),
                       ("Databases", "databases"), ("Authentication", "authentication"),
                       ("Integrations", "external_integrations"), ("Architecture", "architecture_style"),
                       ("Entry points", "entry_points")):
        v = app.get(key)
        v = ", ".join(v) if isinstance(v, list) else v
        parts.append(f"<div><div class=k>{label}</div><div>{_e(v or '-')}</div></div>")
    parts.append("</div>")
    if app.get("components"):
        parts.append("<details><summary>Components</summary><ul>" + "".join(
            f"<li><code>{_e(x.get('path'))}</code> – {_e(x.get('responsibility'))}</li>" for x in app["components"]) + "</ul></details>")
    if app.get("security_observations"):
        parts.append("<details open><summary>Design-level observations</summary><ul>" +
                     "".join(f"<li>{_e(o)}</li>" for o in app["security_observations"] + (app.get("risks_and_gaps") or [])) + "</ul></details>")
    routes = (state.get("discovery") or {}).get("routes", [])
    if routes:
        parts.append(f"<details><summary>{len(routes)} HTTP routes</summary><div class=wrap><table><tr><th>Method</th><th>Path</th><th>Handler</th><th>Auth dep.</th></tr>" +
                     "".join(f"<tr><td>{_e(r['method'])}</td><td><code>{_e(r['path'])}</code></td><td>{_e(r['file'])}:{r['line']} {_e(r['handler'])}</td><td>{'yes' if r.get('auth_dependency') else '<span class=warning>no</span>'}</td></tr>" for r in routes) +
                     "</table></div></details>")
    parts.append("</div>")

    # security
    if sec:
        parts.append("<h2>Security</h2><div class=grid>")
        for s in SEV_ORDER:
            parts.append(f"<div class=card><div class=k>{s}</div><div class='v {s}'>{sev.get(s, 0)}</div></div>")
        parts.append("</div>")
        parts.append(f"<div class=card style='margin-top:12px'><div class=k>Triage ({_e(tri.get('source'))}) · overall risk {_e(tri.get('overall_risk'))}</div><p>{_e(tri.get('executive_summary'))}</p>")
        if tri.get("top_priorities"):
            parts.append("<b>Fix first</b><ol>" + "".join(f"<li>{_e(p)}</li>" for p in tri["top_priorities"]) + "</ol>")
        if tri.get("correlations"):
            parts.append("<b>Correlations</b><ul>" + "".join(f"<li>{_e(p)}</li>" for p in tri["correlations"]) + "</ul>")
        parts.append("</div>")
        parts.append("<h2>Scanners</h2><div class=wrap><table><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Time</th><th>Note</th></tr>" +
                     "".join(f"<tr><td>{_e(s['scanner'])}</td><td class={_e(s['status'])}>{_e(s['status'])}</td><td>{s['findings']}</td><td>{s['duration_s']}s</td><td class=muted>{_e(s['message'][:200])}</td></tr>" for s in sec["scanners"]) +
                     "</table></div>")
        parts.append("<h2>Findings</h2><div class=wrap><table><tr><th>ID</th><th>Severity</th><th>Category</th><th>Location</th><th>Finding &amp; remediation</th></tr>")
        for f in [f for f in sec["findings"] if f["category"] != "code_quality"]:
            tr = f.get("triage") or {}
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            body = f"<b>{_e(f['title'])}</b> <span class=muted>({_e(f['scanner'])}{' + ' + _e(', '.join(f['also_reported_by'])) if f['also_reported_by'] else ''}{' · ' + _e(f['cwe']) if f['cwe'] else ''})</span>"
            if tr.get("verdict"):
                body += f" <span class=badge>{_e(tr['verdict'])}</span>"
            body += f"<div>{_e(tr.get('explanation') or f['description'])[:700]}</div>"
            if tr.get("exploit_scenario"):
                body += f"<div class=muted><i>Exploit:</i> {_e(tr['exploit_scenario'])}</div>"
            body += f"<div><b>Fix:</b> {_e(tr.get('remediation') or f['recommendation'])}</div>"
            if tr.get("fixed_code"):
                body += f"<details><summary>Suggested code</summary><pre>{_e(tr['fixed_code'])}</pre></details>"
            parts.append(f"<tr><td>{f['id']}</td><td><span class='badge {f['severity']}'>{f['severity']}</span></td><td>{_e(f['category'])}</td><td><code>{_e(loc)}</code></td><td>{body}</td></tr>")
        parts.append("</table></div>")
        cq = [f for f in sec["findings"] if f["category"] == "code_quality"]
        if cq:
            parts.append(f"<details><summary>Code quality – {len(cq)} Ruff findings</summary><div class=wrap><table><tr><th>Rule</th><th>Sev</th><th>Location</th><th>Message</th></tr>" +
                         "".join(f"<tr><td>{_e(f['rule_id'])}</td><td class={f['severity']}>{f['severity']}</td><td><code>{_e(f['file'])}:{f['line']}</code></td><td>{_e(f['description'])}</td></tr>" for f in cq[:300]) +
                         "</table></div></details>")

    # gates
    parts.append("<h2>Quality gates</h2><div class=wrap><table><tr><th>Gate</th><th>Check</th><th>Actual</th><th>Required</th><th>Result</th></tr>")
    for gname, g in state.get("gates", {}).items():
        for ch in g["checks"]:
            parts.append(f"<tr><td>{_e(gname)}</td><td>{_e(ch['name'])}</td><td>{_e(ch['actual'])}</td><td>{_e(ch['comparator'])} {_e(ch['threshold'])}</td><td class={'PASS' if ch['passed'] else 'FAIL'}>{'PASS' if ch['passed'] else 'FAIL'}</td></tr>")
        for n in g.get("notes", []):
            parts.append(f"<tr><td>{_e(gname)}</td><td colspan=4 class=muted>{_e(n)}</td></tr>")
    parts.append("</table></div>")
    if state.get("stopped_at"):
        parts.append(f"<p class=FAIL>Pipeline stopped at <b>{_e(state['stopped_at'])}</b>. Re-run with <code>--continue-on-fail</code> to execute the remaining stages anyway.</p>")

    # testing
    if t:
        gen = t.get("generation") or {}
        parts.append("<h2>Testing</h2><div class=grid>" +
                     f"<div class=card><div class=k>Passed</div><div class=v>{t.get('passed', 0)}/{t.get('total', 0)}</div></div>"
                     f"<div class=card><div class=k>Coverage</div><div class=v>{_e(t.get('coverage_percent'))}%</div></div>"
                     f"<div class=card><div class=k>Generated files</div><div class=v>{gen.get('generated_ok', 0)}</div><div class=muted>{_e(gen.get('mode', ''))}</div></div>"
                     f"<div class=card><div class=k>Quarantined / pruned</div><div class=v>{len(gen.get('quarantined', []))} / {len(gen.get('removed_tests', []))}</div></div></div>")
        if t.get("error"):
            parts.append(f"<pre>{_e(t['error'])}</pre>")
        if gen.get("runtime_failures"):
            parts.append("<div class=card style='margin-top:12px'><b class=FAIL>App fails at runtime (caught by smoke tests)</b><ul>" + "".join(f"<li><code>{_e(d['module'])}</code>: {_e(d['error'])}</li>" for d in gen["runtime_failures"]) + "</ul></div>")
        if gen.get("suspected_defects"):
            parts.append("<div class=card style='margin-top:12px'><b>Suspected defects (xfail tests)</b><ul>" + "".join(f"<li><code>{_e(d['module'])}</code>: {_e(d['defect'])}</li>" for d in gen["suspected_defects"]) + "</ul></div>")
        if t.get("failures"):
            parts.append("<details open><summary>Failing tests</summary>" + "".join(f"<div><code>{_e(f['test'])}</code><pre>{_e(f['detail'][-900:])}</pre></div>" for f in t["failures"][:20]) + "</details>")
        if gen.get("quarantined"):
            parts.append("<details><summary>Quarantined generated test files</summary>" + "".join(f"<div><code>{_e(q['module'])}</code><pre>{_e(q['reason'][:900])}</pre></div>" for q in gen["quarantined"]) + "</details>")
        if t.get("coverage_by_file"):
            parts.append("<details><summary>Coverage by file (lowest first)</summary><div class=wrap><table><tr><th>File</th><th>%</th></tr>" +
                         "".join(f"<tr><td><code>{_e(k)}</code></td><td>{v}</td></tr>" for k, v in list(t["coverage_by_file"].items())[:60]) + "</table></div></details>")

    # container
    if c:
        csev = (c.get("scan") or {}).get("by_severity", {})
        parts.append("<h2>Container</h2><div class=grid>" +
                     f"<div class=card><div class=k>Dockerfile</div><div class=v>{_e(c.get('dockerfile_source', '-'))}</div></div>"
                     f"<div class=card><div class=k>Image</div><div>{_e(c.get('image', c.get('message', '-')))}</div><div class=muted>{_e(c.get('size_mb', ''))} MB</div></div>"
                     f"<div class=card><div class=k>Smoke run</div><div class='v {_e((c.get('smoke') or {}).get('status', ''))}'>{_e((c.get('smoke') or {}).get('status', 'n/a'))}</div><div class=muted>HTTP probe: {_e((c.get('smoke') or {}).get('http_probe'))}</div></div>"
                     f"<div class=card><div class=k>Image vulns C/H/M/L</div><div class=v>{csev.get('CRITICAL', 0)}/{csev.get('HIGH', 0)}/{csev.get('MEDIUM', 0)}/{csev.get('LOW', 0)}</div><div class=muted>{_e((c.get('scan') or {}).get('os', ''))} · fixable {_e((c.get('scan') or {}).get('fixable', 0))}</div></div></div>")
        if (c.get("smoke") or {}).get("logs_tail") and c["smoke"].get("status") != "passed":
            parts.append(f"<details open><summary>Container start-up logs</summary><pre>{_e(c['smoke']['logs_tail'])}</pre></details>")
        if c.get("message") and not c.get("image_built"):
            parts.append(f"<pre>{_e(c['message'])}</pre>")
        lint = c.get("dockerfile_lint") or {}
        if lint.get("issues"):
            parts.append("<h2>Dockerfile checks</h2><div class=wrap><table><tr><th>Rule</th><th>Severity</th><th>Line</th><th>Issue</th></tr>" +
                         "".join(f"<tr><td>{_e(i['rule'])}</td><td class={i['severity']}>{i['severity']}</td><td>{i['line'] or ''}</td><td>{_e(i['message'])}</td></tr>" for i in lint["issues"]) + "</table></div>")
        if c.get("dockerfile"):
            parts.append(f"<details><summary>Dockerfile</summary><pre>{_e(c['dockerfile'])}</pre></details>")
        top = [f for f in (c.get("scan") or {}).get("findings", []) if f["severity"] in ("CRITICAL", "HIGH")][:40]
        if top:
            parts.append("<details><summary>Critical/high image vulnerabilities</summary><div class=wrap><table><tr><th>Sev</th><th>Package</th><th>Installed</th><th>Fixed</th><th>ID</th></tr>" +
                         "".join(f"<tr><td class={f['severity']}>{f['severity']}</td><td>{_e(f['package'])}</td><td>{_e(f['installed_version'])}</td><td>{_e(f['fixed_version'] or '—')}</td><td>{_e(f['cve'])}</td></tr>" for f in top) + "</table></div></details>")

    # stages + artifacts
    parts.append("<h2>Pipeline stages</h2><div class=wrap><table><tr><th>Stage</th><th>Status</th><th>Time</th><th>Detail</th></tr>" +
                 "".join(f"<tr><td>{_e(s['stage'])}</td><td class={_e(s['status'])}>{_e(s['status'])}</td><td>{s['duration_s']}s</td><td class=muted>{_e(str(s.get('message', ''))[:220])}</td></tr>" for s in state["stages"]) + "</table></div>")
    parts.append("<h2>Artifacts</h2><ul>" + "".join(f"<li>{_e(a['kind'])}: <code>{_e(a['path'])}</code></li>" for a in state.get("artifacts", [])) + "</ul>")
    if state.get("crash"):
        parts.append(f"<h2 class=FAIL>Pipeline error</h2><pre>{_e(state['crash'])}</pre>")
    parts.append(f"<p class=muted>LLM usage: {_e(json.dumps(state.get('llm_usage', {})))}</p></main></body></html>")
    return "\n".join(parts)


def write_reports(state: dict, run_dir: Path) -> dict:
    paths = {"json": run_dir / "assessment_report.json", "markdown": run_dir / "assessment_report.md",
             "html": run_dir / "assessment_report.html"}
    write_json(paths["json"], state)
    paths["markdown"].write_text(render_markdown(state), encoding="utf-8")
    paths["html"].write_text(render_html(state), encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}
