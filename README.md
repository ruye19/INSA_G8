# EthioScan: Ethiopia-Ready Web Vulnerability Scanner

## 📌 Overview  
EthioScan helps Ethiopian teams find and fix the most important **web and API security issues—fast**.  
The tool systematically analyzes applications using crawling, scanning, and fuzzing to detect common vulnerabilities like:

- Cross-Site Scripting (XSS)  
- SQL Injection (SQLi)  
- Insecure Direct Object References (IDOR)  

EthioScan generates detailed, **evidence-rich reports** with clear remediation steps.  
Our goal: **less noise, more fixes** — built to work under low bandwidth, support local languages, and enforce legal, allowlisted testing.  

---

## 🚨 The Problem (Ethiopia in simple terms)

1. **We don’t know the real risk**  
   - Scanners produce long lists. Teams waste time on low-impact issues while high-risk ones remain.  

2. **Modern apps are hard to scan**  
   - SPAs (React/Vue) and APIs need smarter crawling + login handling.  
   - Basic spiders miss important routes and parameters.  

3. **Reports don’t help decision-makers**  
   - Leaders need summaries (local languages) and proof the issue is real.  
   - Without evidence + guidance, fixes stall.  

✅ **EthioScan solves this** with:  
- Risk-based ranking  
- SPA/API-aware crawling  
- Proof-based reports with bilingual support  

---

## 🎯 Features

- **Systematic analysis:** crawling → scanning → fuzzing  
- **Crawling:** SPA-smart with Playwright + classic spider  
- **Scanning:** OWASP Top 10 (auth/session, headers, TLS)  
- **Fuzzing:** Safe payloads for XSS, SQLi, IDOR  
- **Web + API testing:** Import OpenAPI, auto-generate requests, abuse tests  
- **Risk-aware ranking:** CVSS + EPSS/KEV indicators  
- **Evidence-first reports:** Screenshots, curl repro, request/response logs  
- **Delta & Verify Fix:** Track changes and confirm patches  
- **Login support:** Form + OIDC/OAuth2 profiles  
- **Allowlist-enforced legality**  
- **Low-bandwidth/offline-friendly**  
- **Localization:** Executive summaries in Amharic, Afan Oromo, Tigrinya  

---

## 🛠 Tech Stack

- **Language:** Python 3.x  
- **Crawler:** Playwright (headless Chromium) + spider  
- **Checks & fuzzing:** Custom Python probes (OWASP XSS/SQLi/IDOR, headers, TLS)  
- **API Mode:** OpenAPI import + abuse tests  
- **Risk:** CVSS + EPSS/KEV  
- **DB:** SQLite (dev) → Postgres (prod)  
- **Workers:** Redis + RQ/Celery  
- **Reports:** Jinja2 → HTML → PDF (WeasyPrint/wkhtmltopdf)  
- **UI:** HTML/CSS + Chart.js  

---

## 🧩 System Architecture

**Ingestion → Scan (crawl/scan/fuzz) → Prioritize → Report**

1. **Targets & Auth** – URLs, OpenAPI, login flows (form/OIDC)  
2. **Crawling** – Playwright for SPAs, spider for static links  
3. **Checks & Fuzzing** – OWASP checks + safe payloads  
4. **Risk Engine** – CVSS + EPSS/KEV ranking  
5. **Evidence** – Screenshots, curl repro, request/response  
6. **Reports** – Executive summary (local language) + technical appendix  

---

## 📁 Project Structure

```
ethioscan/
├── app.py                         # API + dashboard entrypoint
├── config.py                      # settings, secrets, rate limits
├── auth/
│   ├── form_login.py              # form login
│   └── oidc_client.py             # OIDC/OAuth2 flows
├── crawl/
│   ├── playwright_crawler.py      # SPA-aware crawler
│   └── spider.py                  # classic crawler
├── checks/
│   ├── web/
│   │   ├── injections.py          # SQLi/XSS
│   │   ├── idor.py                # IDOR checks
│   │   ├── headers.py             # CSP/HSTS checks
│   │   └── tls.py                 # TLS/cipher checks
│   ├── api/
│   │   ├── openapi_runner.py      # OpenAPI requests
│   │   └── abuse_tests.py         # rate-limit, auth
│   └── utils/
│       ├── payloads.py            # fuzz payloads
│       ├── evidence.py            # screenshots, curl repro
│       └── suppression.py         # false positives
├── risk/
│   ├── cvss.py
│   └── rank.py
├── store/
│   ├── models.py                  # DB models
│   └── db.sqlite3                 # dev DB
├── queue/
│   └── worker.py
├── reporting/
│   ├── templates/
│   │   ├── exec_summary_am.html   # Amharic
│   │   ├── exec_summary_en.html   # English
│   │   └── technical.html
│   └── export.py
├── policies/
│   ├── allowlist.txt
│   └── scan_profiles.yml
├── ui/
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── finding.html
│   └── static/
├── tests/
│   └── test_*.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.10+  
- Playwright browser dependencies  
- (Optional) Redis, Docker  

### Clone
```bash
git clone https://github.com/your-username/ethioscan.git
cd ethioscan
```

### Environment
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

### Playwright
```bash
python -m playwright install --with-deps
```

### Run (Dev)
```bash
# API + Dashboard
python app.py  

# Worker (optional)
python queue/worker.py
```

👉 Open: [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard)

⚖️ **Authorization**: Add permitted targets to `policies/allowlist.txt`.  
EthioScan refuses active scans for domains not on the allowlist.  

---

## 🧪 Testing

- Lab targets: **OWASP Juice Shop / DVWA** (with authorization)  
- API mode: Import OpenAPI, test parameters  
- Fuzzing: Validate detection of XSS/SQLi/IDOR  
- Evidence: Confirm screenshots + curl repro  
- Delta & Verify Fix: Add CSP header → re-scan → confirm fix  

### CLI/API Example
```bash
curl -X POST http://127.0.0.1:5000/api/targets   -H "Content-Type: application/json"   -d '{"url":"http://juice-shop.local"}'

curl -X POST http://127.0.0.1:5000/api/scans   -H "Content-Type: application/json"   -d '{"target_id":1,"profile":"safe_baseline"}'
```

---

## 👥 Team Roles
- **Crawler & Auth Lead** – SPA crawling, login flows  
- **Checks & Risk Lead** – Fuzzing, OWASP tests, CVSS ranking  
- **Backend & Queue Lead** – API, Redis, DB models, allowlist enforcement  
- **UI & Reporting Lead** – Dashboard, bilingual reports, Delta/Verify Fix  

---

## 🚀 Future Improvements
- CI/CD Gatekeeper (GitHub/GitLab plugins)  
- GraphQL Mode  
- Auth Macro Recorder  
- Plugin SDK  
- Service Context & SCA Hints  
- Noise Governance & False-Positive Analytics  
- Multi-Tenant SaaS + Offline Agents  
- Auto-Remediation Templates (Nginx/Apache/CSP)  
- Stakeholder Templates in Amharic/Afan Oromo/Tigrinya  
- Regional Benchmarks (.et)  

---

## 📜 License
MIT License — for personal and educational use only.  
⚠️ Active scanning must only be performed on **authorized assets**.  

---

## 📧 Contact
- **Email:** ruthye64@example.com  
- **GitHub:** [ruye19](https://github.com/ruye19)  
- **Telegram:** [@noirHazel](https://t.me/noirHazel)  
