import datetime

def generate_report():
    """
    Dummy report generator.
    Later, export to PDF/CSV/HTML.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("scan_report.txt", "w") as f:
        f.write(f"EthioScan Report - {now}\n")
        f.write("All systems secure ✅\n")
