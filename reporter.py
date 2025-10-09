from jinja2 import Environment, FileSystemLoader
import json
from datetime import datetime
import os

def generate_report(findings_file: str, output_file: str):
    """
    Generate an HTML report from JSON scan findings.

    Args:
        findings_file: Path to JSON file containing scan findings.
        output_file: Path to save the HTML report.
    """
    # Load findings JSON
    try:
        with open(findings_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[Error] Findings file '{findings_file}' not found.")
        return
    except json.JSONDecodeError:
        print(f"[Error] Findings file '{findings_file}' is not valid JSON.")
        return

    # Extract scan info and findings
    scan_info = data.get("scan_info", {})
    findings = data.get("findings", [])

    # Prepare severity counts for color-coding
    severity_colors = {
        "critical": "red",
        "high": "red",
        "medium": "orange",
        "low": "green",
        "unknown": "gray"
    }

    # Ensure all findings have necessary keys
    for f in findings:
        f.setdefault("id", "-")
        f.setdefault("url", "-")
        f.setdefault("param", "-")
        f.setdefault("payload", "-")
        f.setdefault("category", "-")
        f.setdefault("severity", "unknown")
        f.setdefault("evidence", "-")
        f["color"] = severity_colors.get(f["severity"].lower(), "gray")

    # Load Jinja2 template
    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=True
    )
    template = env.get_template("report_template.html")

    # Render HTML
    html_content = template.render(
        scan_info=scan_info,
        findings=findings,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Save HTML
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[Success] Report generated: {output_file}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python -m ethioscan.reporter <findings_json> <output_html>")
        print("Example: python -m ethioscan.reporter examples/sample_findings.json examples/report.html")
        sys.exit(1)
    
    findings_file = sys.argv[1]
    output_file = sys.argv[2]
    
    generate_report(findings_file, output_file)
