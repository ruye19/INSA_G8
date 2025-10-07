from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
import subprocess, threading, time, pathlib, json
from datetime import datetime

app = FastAPI(title="EthioScan Dashboard")

# --- Fix path resolution ---
BASE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPORTS_DIR = BASE_DIR / "examples"

print(f"[DEBUG] Dashboard initialized. Reports dir: {REPORTS_DIR.resolve()}")

# Static & templates
app.mount("/static", StaticFiles(directory=str(pathlib.Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))

ACTIVE_SCANS = {}


def load_reports():
    """Load all completed JSON reports from /examples"""
    reports = []
    if not REPORTS_DIR.exists():
        print(f"[WARN] Reports directory not found: {REPORTS_DIR}")
        return reports

    for file in REPORTS_DIR.glob("*.json"):
        try:
            data = json.loads(file.read_text())
            findings = data.get("findings", [])
            high = sum(1 for f in findings if f.get("severity") == "High")
            medium = sum(1 for f in findings if f.get("severity") == "Medium")
            low = sum(1 for f in findings if f.get("severity") == "Low")
            reports.append({
                "file": file.name,
                "target": data.get("target") or data.get("meta", {}).get("target", "unknown"),
                "total": len(findings),
                "high": high,
                "medium": medium,
                "low": low,
                "date": datetime.fromtimestamp(file.stat().st_mtime).strftime("%b %d, %Y %H:%M:%S"),
                "status": "Completed"
            })
        except Exception as e:
            print(f"[WARN] Failed to load {file.name}: {e}")
            continue

    reports.sort(key=lambda x: x["date"], reverse=True)
    print(f"[DEBUG] Loaded {len(reports)} reports.")
    return reports


@app.get("/")
async def dashboard(request: Request):
    reports = load_reports()

    # Merge active scans
    for url, info in ACTIVE_SCANS.items():
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
    file = REPORTS_DIR / filename
    if not file.exists():
        return templates.TemplateResponse("report_template.html", {"request": request, "error": "Report not found"})
    try:
        data = json.loads(file.read_text())
        return templates.TemplateResponse("report_template.html", {"request": request, "report": data})
    except Exception as e:
        return templates.TemplateResponse(
            "report_template.html",
            {"request": request, "error": f"Failed to load report: {str(e)}"}
        )


@app.post("/scan")
async def new_scan(url: str = Form(...)):
    """Trigger a scan asynchronously and track its progress."""
    try:
        ACTIVE_SCANS[url] = {"start_time": time.time()}
        print(f"[DEBUG] Starting scan for {url}")

        cmd = ["python", "-m", "ethioscan.cli", "--url", url, "--confirm-allow", "I_HAVE_PERMISSION"]

        def run_scan():
            subprocess.call(cmd)
            # Wait for a report file to appear
            for _ in range(60):  # up to ~2 min
                for file in REPORTS_DIR.glob("*.json"):
                    try:
                        if url in file.read_text():
                            ACTIVE_SCANS.pop(url, None)
                            print(f"[DEBUG] Scan finished for {url}, report: {file.name}")
                            return
                    except Exception:
                        continue
                time.sleep(2)
            ACTIVE_SCANS.pop(url, None)
            print(f"[WARN] Scan timeout: no report found for {url}")

        threading.Thread(target=run_scan, daemon=True).start()
        return JSONResponse({"status": "started", "url": url})
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
