from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
import subprocess, threading, time, pathlib, json
from datetime import datetime
from collections import Counter

app = FastAPI(title="EthioScan Dashboard")

# --- Path setup ---
BASE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPORTS_DIR = BASE_DIR / "examples"
print(f"[DEBUG] Dashboard initialized. Reports dir: {REPORTS_DIR.resolve()}")

# --- Static & Templates ---
STATIC_DIR = pathlib.Path(__file__).parent / "static"
TEMPLATES_DIR = pathlib.Path(__file__).parent / "templates"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Track running scans
ACTIVE_SCANS = {}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _build_summary(findings):
    """Summarize by severity, category, and URL (case-insensitive)."""
    sev_counts = Counter((f.get("severity") or "unknown").strip().capitalize() for f in findings)
    cat_counts = Counter((f.get("category") or "unknown").strip().capitalize() for f in findings)
    url_counts = Counter(f.get("url") or f.get("final_url") or "N/A" for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(sev_counts),
        "by_category": dict(cat_counts),
        "by_url": dict(url_counts),
    }


def _normalize_report(raw):
    """Normalize schema to the template expectation."""
    scan_info = raw.get("scan_info", {})
    findings = raw.get("findings", [])

    meta = {
        "target": scan_info.get("target_url", raw.get("target", "unknown")),
        "generated_at": scan_info.get("scan_time")
            or scan_info.get("generated_at")
            or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "depth": scan_info.get("depth", "-"),
        "concurrency": scan_info.get("concurrency", "-"),
        "tests_run": scan_info.get("tests_executed", "-"),
        "report_format": "html",
    }

    summary = _build_summary(findings)

    normalized_findings = []
    for f in findings:
        normalized_findings.append({
            "category": f.get("category", "-"),
            "severity": (f.get("severity") or "Unknown").strip().capitalize(),
            "url": f.get("url") or f.get("final_url") or "-",
            "param": f.get("param", "-"),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
        })

    return {"meta": meta, "summary": summary, "findings": normalized_findings}


def load_reports():
    """Load and summarize all JSON reports for dashboard."""
    reports = []
    if not REPORTS_DIR.exists():
        print(f"[WARN] Reports directory not found: {REPORTS_DIR}")
        return reports

    for file in REPORTS_DIR.glob("*.json"):
        try:
            raw = json.loads(file.read_text(encoding="utf-8"))
            findings = raw.get("findings", [])
            normalized = [(f.get("severity") or "").strip().lower() for f in findings]

            high = normalized.count("high")
            medium = normalized.count("medium")
            low = normalized.count("low")

            target = (raw.get("scan_info") or {}).get("target_url") \
                     or raw.get("target") \
                     or (raw.get("meta") or {}).get("target", "unknown")

            reports.append({
                "file": file.name,
                "target": target,
                "total": len(findings),
                "high": high,
                "medium": medium,
                "low": low,
                "date": datetime.fromtimestamp(file.stat().st_mtime)
                        .strftime("%b %d, %Y %H:%M:%S"),
                "status": "Completed"
            })
        except Exception as e:
            print(f"[WARN] Failed to load {file.name}: {e}")
            continue

    reports.sort(key=lambda x: x["date"], reverse=True)
    print(f"[DEBUG] Loaded {len(reports)} reports.")
    return reports

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def dashboard(request: Request):
    """Render dashboard overview."""
    reports = load_reports()

    for url in list(ACTIVE_SCANS.keys()):
        reports.insert(0, {
            "file": "pending",
            "target": url,
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "date": datetime.now().strftime("%b %d, %Y %H:%M:%S"),
            "status": "In Progress"
        })

    return templates.TemplateResponse("index.html", {"request": request, "reports": reports})


@app.get("/report/{filename}")
async def report_detail(request: Request, filename: str):
    """Render detailed report view."""
    file = REPORTS_DIR / filename
    print(f"[DEBUG] Opening report: {file}")

    if not file.exists():
        return templates.TemplateResponse("report_template.html", {
            "request": request,
            "error": f"Report not found: {filename}"
        })

    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
        report = _normalize_report(raw)
        return templates.TemplateResponse("report_template.html", {
            "request": request,
            "report": report
        })
    except Exception as e:
        print(f"[ERROR] Failed to load report: {e}")
        return templates.TemplateResponse("report_template.html", {
            "request": request,
            "error": f"Failed to load report: {e}"
        })


@app.post("/scan")
async def new_scan(url: str = Form(...)):
    """Start a scan and track it."""
    try:
        ACTIVE_SCANS[url] = {"start_time": time.time()}
        print(f"[DEBUG] Starting scan for {url}")

        cmd = ["python", "-m", "ethioscan.cli", "--url", url, "--confirm-allow", "I_HAVE_PERMISSION"]

        def run_scan():
            subprocess.call(cmd)
            for _ in range(60):
                for f in REPORTS_DIR.glob("*.json"):
                    try:
                        if url in f.read_text(encoding="utf-8"):
                            ACTIVE_SCANS.pop(url, None)
                            print(f"[DEBUG] Scan finished for {url}: {f.name}")
                            return
                    except Exception:
                        continue
                time.sleep(2)
            ACTIVE_SCANS.pop(url, None)
            print(f"[WARN] Timeout: no report for {url}")

        threading.Thread(target=run_scan, daemon=True).start()
        return JSONResponse({"status": "started", "url": url})
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
