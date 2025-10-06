from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound

TEMPLATES_DIR = Path("templates")
TEMPLATE_NAME = "report_template.html"


# ---------------------------
# Helpers
# ---------------------------
def _norm_sev(v: Dict[str, Any]) -> str:
    return (v.get("severity") or "unknown").lower()


def _sev_color(sev: str) -> str:
    sev = sev.lower()
    if sev == "critical":
        return "red"
    if sev == "high":
        return "darkorange"
    if sev == "medium":
        return "goldenrod"
    if sev == "low":
        return "steelblue"
    return "gray"


def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate findings by severity, category, and URL."""
    by_sev: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    by_url: Dict[str, int] = {}
    for f in findings or []:
        sev = _norm_sev(f)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = (f.get("category") or "unknown").lower()
        by_cat[cat] = by_cat.get(cat, 0) + 1
        url = f.get("url") or f.get("final_url") or "unknown"
        by_url[url] = by_url.get(url, 0) + 1
    return {
        "total": len(findings or []),
        "by_severity": by_sev,
        "by_category": dict(sorted(by_cat.items())),
        "by_url": dict(sorted(by_url.items())),
    }


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------
# Rendering
# ---------------------------
def _render_html(meta: Dict[str, Any], findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    try:
        tpl = env.get_template(TEMPLATE_NAME)
        return tpl.render(meta=meta, findings=findings, summary=summary)
    except TemplateNotFound:
        return _fallback_html(meta, findings, summary)


def _fallback_html(meta: Dict[str, Any], findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    """Minimal fallback if template is missing."""
    rows = []
    for f in findings or []:
        payload = f.get("payload")
        if isinstance(payload, dict):
            payload = payload.get("payload", str(payload))
        rows.append(
            f"<tr>"
            f"<td>{f.get('category','')}</td>"
            f"<td><span style='color:{_sev_color(f.get('severity',''))}; font-weight:bold'>{f.get('severity','')}</span></td>"
            f"<td><code>{(f.get('url') or f.get('final_url') or '')}</code></td>"
            f"<td>{f.get('param','')}</td>"
            f"<td><code>{payload}</code></td>"
            f"<td><pre style='white-space:pre-wrap'>{(f.get('evidence','')[:500])}</pre></td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>EthioScan Report</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f5f5f5; text-align: left; }}
    code {{ background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>EthioScan Report</h1>
  <p>
    Target: <strong>{meta.get('target','')}</strong> • 
    Generated: {meta.get('generated_at','')} • 
    Depth: {meta.get('depth','-')} • 
    Concurrency: {meta.get('concurrency','-')} • 
    Tests run: {meta.get('tests_run','-')}
  </p>

  <h2>Summary</h2>
  <ul>
    <li>Total Findings: <strong>{summary['total']}</strong></li>
    <li>By Severity:</li>
    <ul>
      {''.join(f'<li><span style="color:{_sev_color(sev)}; font-weight:bold">{sev.capitalize()}</span>: {count}</li>' for sev, count in summary['by_severity'].items())}
    </ul>
    <li>By Category:</li>
    <ul>
      {''.join(f'<li>{cat.upper()}: {count}</li>' for cat, count in summary['by_category'].items())}
    </ul>
  </ul>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Category</th><th>Severity</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th></tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="6">No issues found.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


# ---------------------------
# Generators
# ---------------------------
def generate_json_report(meta: Dict[str, Any], findings: List[Dict[str, Any]], out_file: str) -> str:
    """Write JSON report."""
    data = {
        "meta": meta,
        "findings": findings or [],
        "summary": _summarize(findings),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    path = Path(out_file)
    _ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path.resolve())


def generate_html_report(meta: Dict[str, Any], findings: List[Dict[str, Any]], out_file: str) -> str:
    """Write HTML report, fallback if template not found."""
    summary = _summarize(findings)
    meta = dict(meta or {})
    meta.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")
    html = _render_html(meta, findings or [], summary)
    path = Path(out_file)
    _ensure_parent(path)
    path.write_text(html, encoding="utf-8")
    return str(path.resolve())


def save_report(
    meta: Dict[str, Any],
    findings: List[Dict[str, Any]],
    report_format: str,
    out_file: str,
    tests_run: int | None = None,
) -> str:
    """Save EthioScan report in HTML or JSON."""
    meta = dict(meta or {})
    if tests_run is not None:
        meta["tests_run"] = tests_run
    meta.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")

    if report_format == "json":
        return generate_json_report(meta, findings, out_file)
    return generate_html_report(meta, findings, out_file)
