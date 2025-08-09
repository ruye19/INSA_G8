# 🛡️ PhishShield  
**Smart URL and File Threat Detection for Web Applications**

---

## 📌 Overview

PhishShield is a **Python-powered web security tool** that detects **phishing links** and **malware-infected files** in real-time.  
It acts as a **security layer** for web platforms where users upload files or share URLs.  
The system integrates with **threat intelligence APIs** and local scanning tools to block dangerous content before it causes harm.

This project is built for **practical use in national companies** and educational purposes, focusing on **real-world security threats**.

---

## 🚨 Problem Statement

Phishing remains one of the most common and damaging forms of cyberattacks, tricking users into revealing sensitive information such as passwords, banking details, or personal data. While phishing attempts often occur through email, messaging platforms have become a major hotspot for these attacks.

One of the most vulnerable platforms in this regard is **Telegram**, where cybercriminals exploit public groups, channels, and private messages to share malicious links, fake login pages, and malware-infected files. Due to Telegram’s popularity, ease of file sharing, and lack of strict link scanning, it has become a significant distribution point for phishing campaigns.

Currently, many users—especially in developing nations—lack the technical awareness or tools to detect these threats before falling victim. This gap calls for a lightweight, accessible, and real-time phishing detection tool.

**PhishShield** aims to address this by:  
- Scanning suspicious URLs for phishing patterns and known malicious domains.  
- Analyzing shared files for hidden malware signatures.  
- Offering an easy-to-use interface for quick checks before users interact with potentially harmful content.  
- Providing optional integration with Telegram bots to automatically detect and flag phishing attempts in chats or channels.

By empowering users to identify threats before engaging, **PhishShield** will reduce the impact of phishing attacks and protect sensitive data in everyday communication.

---

## 🎯 Features

- 🔗 **URL Threat Detection** – Scans URLs for phishing, malware, or blacklisted domains  
- 📎 **File Malware Scanning** – Checks PDFs, DOCX, ZIP, and other files for malicious content  
- 📊 **Admin Dashboard** – Displays threat logs with timestamps, sources, and reasons  
- 🔔 **Alert System** – Notifies admins of blocked threats  
- 🧪 **Testing Support** – Works with DVWA, Kali Linux, and EICAR test files for simulation  

---

## 🛠️ Tech Stack

**Backend:**  
- Python  
- Flask  

**Threat Detection:**  
- VirusTotal API (for URLs)  
- ClamAV (for file scanning)  

**Frontend:**  
- HTML  
- CSS  
- Chart.js (for dashboard charts)  

**Database:**  
- SQLite (for logs)  

**Testing Tools:**  
- Kali Linux  
- DVWA (Damn Vulnerable Web App)  
- EICAR test file  

---

## 🧩 System Architecture

1. **User Uploads File or URL** via web form  
2. **Request Interception** in Flask backend  
3. **Scanning Stage**:  
   - URLs → VirusTotal API  
   - Files → ClamAV local scan  
4. **Decision**:  
   - If clean → Allow  
   - If malicious → Block & log incident  
5. **Dashboard Logging** – Incident stored in SQLite and shown in dashboard  

---

## 📁 Project Structure

phishshield/
├── app.py                 # Main Flask application
├── scanners/              # Threat scanning modules
│   ├── url_scanner.py     # URL scanning logic (VirusTotal API)
│   ├── file_scanner.py    # File scanning logic (ClamAV)
├── templates/             # HTML templates for the web UI
│   ├── dashboard.html     # Admin dashboard page
│   ├── upload.html        # File/URL upload page
├── static/                # Static files (CSS, JS, Images)
│   ├── style.css          # Dashboard styling
│   └── script.js          # Optional JS for frontend interactivity
├── logs/                  # Database and log storage
│   └── threats.db         # SQLite database storing incidents
├── tests/                 # Test data and scripts
│   ├── sample_data/       # Safe test URLs/files (EICAR, etc.)
│   └── test_app.py        # Unit tests for scanning functions
├── requirements.txt       # Python dependencies
├── .env                   # API keys and sensitive config
└── README.md              # Project documentation

---

## 📦 Installation & Setup

1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/your-username/phishshield.git
cd phishshield
2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
3️⃣ Set up ClamAV (Linux example)

```bash
sudo apt install clamav
sudo freshclam  # update virus database
4️⃣ Add VirusTotal API Key

Get your free API key from VirusTotal

Store it in a .env file or inside url_scanner.py

5️⃣ Run the Application

```bash

python app.py
6️⃣ Open Dashboard

Visit: http://127.0.0.1:5000/dashboard

🧪 Testing the System
You can test PhishShield with:

EICAR test file (download here) – Simulates a virus safely

DVWA – Use for simulating SQLi/XSS + file uploads

Malicious URL lists from PhishTank or VirusTotal samples

Kali Linux attack tools – For controlled penetration testing

📊 Dashboard Preview
The admin dashboard will show:

Threat type (Phishing Link / Malware File)

Reason for detection

Timestamp of incident

Source/User info

👥 Team Roles
Ruth Yeshitila – Core Logic & URL/File Scanning

Member 2 – Flask Routing & Middleware Development

Member 3 – Dashboard UI & Logging System

Member 4 – Testing, Documentation & Report

🚀 Future Improvements
Machine Learning model for zero-day phishing detection

Real-time email scanning integration

Cloud deployment with Docker for scalability

Multi-language dashboard interface

📜 License
MIT License — free for personal and educational use.

📧 Contact
For inquiries or contributions:
Email: ruthye64gmail@example.com
GitHub: ruye19


---

If you want, I can also **generate the matching `requirements.txt`** and **scaffold the folder structure** so your team can just clone it and start coding.  
Do you want me to prepare that next?
