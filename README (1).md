# EthioScan: Ethiopia-Ready Web Vulnerability Scanner

## 📌 Overview
EthioScan is a **web and API vulnerability scanner** designed with a focus on Ethiopian organizations and developers. It helps teams quickly identify and remediate the most critical security issues, ensuring safer applications and compliance with best practices.

The tool combines **crawling, scanning, and fuzzing** to detect vulnerabilities such as:
- 🔓 **SQL Injection (SQLi)**
- 🛡️ **Cross-Site Scripting (XSS)**
- 🔐 **Broken Authentication**
- 📂 **Directory Traversal**
- ⚠️ **Insecure HTTP Headers**
- 🌐 **Open Ports & Services Misconfigurations**

EthioScan is **lightweight, fast, and Ethiopia-ready** — designed to empower local developers, startups, and institutions.

---

## 🚀 Features
✅ Automated crawling & scanning of web applications  
✅ Detection of **common OWASP Top 10 vulnerabilities**  
✅ API security testing with fuzzing support  
✅ Detailed **HTML/JSON reports** for developers & managers  
✅ Easy-to-use **CLI interface**  
✅ Built with **Python** for extensibility  

---

## 🛠️ Tech Stack
- **Language**: Python 3.10+  
- **Libraries**:  
  - `requests` – HTTP requests  
  - `beautifulsoup4` – HTML parsing  
  - `aiohttp` – async scanning  
  - `colorama` – terminal highlights  
  - `rich` – pretty reporting  
- **Database (optional)**: SQLite (for scan history)  

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ethioscan.git
cd ethioscan

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

Run a scan against a target URL:

```bash
python ethioscan.py --url https://example.com
```

Options:
```bash
--url          Target website or API endpoint
--depth        Crawling depth (default: 2)
--report       Output report format: json/html (default: html)
--out          Save report to file (default: report.html)
```

Example:
```bash
python ethioscan.py --url https://gov.et --depth 3 --report html --out gov-report.html
```

---

## 📊 Reports

EthioScan generates detailed reports in **HTML** and **JSON** format, including:
- Vulnerability type & severity
- Affected endpoints
- Suggested remediation steps

---

## 🤝 Contributing

We welcome contributions!  
- Open issues for bug reports or feature requests  
- Submit PRs for improvements  

---

## 📜 License

MIT License © 2025 EthioScan Team
