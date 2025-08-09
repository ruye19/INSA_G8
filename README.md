
# 🛡️ PhishShield: Smart URL and File Threat Detection

## 📌 Overview

PhishShield is a **Python-powered web security tool** designed to detect and block malicious content in real time. It acts as a security layer for web applications, scanning suspicious URLs and files to prevent phishing and malware attacks.

This project is built for practical use, focusing on real-world security threats in corporate and educational environments. It integrates with industry-standard threat intelligence APIs and local scanning tools to offer robust, proactive protection.

-----

## 🚨 The Problem

Phishing remains one of the most prevalent and damaging cyberattacks, tricking users into revealing sensitive information. While many attacks occur via email, platforms like **Telegram** have become major hotspots for distributing malicious links and files.

Cybercriminals exploit Telegram's popularity and file-sharing ease, often targeting users who lack the technical knowledge to identify these threats. This creates a significant gap in digital security, especially in regions where awareness and tools are limited.

**PhishShield** addresses this by:

  * Scanning suspicious URLs for phishing patterns and known malicious domains.
  * Analyzing shared files for malware signatures.
  * Providing an intuitive interface for quick checks.
  * Offering optional integration with platforms like Telegram to automatically flag threats in chats and channels.

By empowering users to identify threats before they interact with them, PhishShield significantly reduces the impact of phishing and malware attacks.

-----

## 🎯 Features

  * **URL Threat Detection:** Scans URLs against threat intelligence databases for phishing, malware, and blacklisted domains.
  * **File Malware Scanning:** Analyzes uploaded files (PDFs, DOCX, ZIP, etc.) for malicious content using a local scanner.
  * **Admin Dashboard:** Provides a centralized view of all security logs, including threat type, timestamp, and source.
  * **Real-time Alerts:** Notifies administrators of blocked threats.
  * **Testing Support:** Compatible with tools like DVWA, Kali Linux, and EICAR test files for comprehensive security testing and simulation.

-----

## 🛠️ Tech Stack

**Backend:** Python, Flask

**Threat Detection:**

  * VirusTotal API (for URLs)
  * ClamAV (for file scanning)

**Frontend:** HTML, CSS, Chart.js

**Database:** SQLite (for threat logs)

**Testing Tools:** Kali Linux, DVWA, EICAR test file

-----

## 🧩 System Architecture

1.  **User Interaction:** A user uploads a file or submits a URL via the web interface.
2.  **Request Handling:** The Flask backend intercepts the request.
3.  **Threat Scanning:**
      * URLs are sent to the VirusTotal API for analysis.
      * Files are scanned locally using ClamAV.
4.  **Decision & Action:**
      * If the content is clean, it is allowed to proceed.
      * If malicious, the content is blocked, and the incident is logged.
5.  **Dashboard Logging:** The incident details are stored in the SQLite database and displayed on the admin dashboard.

-----

## 📁 Project Structure

```
phishshield/
├── app.py                     # Main Flask application
├── scanners/                  # Threat scanning modules
│   ├── url_scanner.py         # URL scanning logic (VirusTotal API)
│   └── file_scanner.py        # File scanning logic (ClamAV)
├── templates/                 # HTML templates for the web UI
│   ├── dashboard.html         # Admin dashboard page
│   └── upload.html            # File/URL upload page
├── static/                    # CSS, JS, and images
│   ├── style.css              # Dashboard styling
│   └── script.js              # Frontend interactivity (optional)
├── logs/                      # Database and log storage
│   └── threats.db             # SQLite database for incidents
├── tests/                     # Test data and scripts
│   ├── sample_data/           # Safe test URLs/files (EICAR, etc.)
│   └── test_app.py            # Unit tests for scanning functions
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables (e.g., API keys)
└── README.md                  # Project documentation
```

-----

## 📦 Installation & Setup

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/your-username/phishshield.git
    cd phishshield
    ```

2.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up ClamAV (Linux example)**

    ```bash
    sudo apt install clamav
    sudo freshclam # Update the virus database
    ```

4.  **Add VirusTotal API Key**

      * Obtain a free API key from VirusTotal.
      * Create a `.env` file in the project root and add your key: `VIRUSTOTAL_API_KEY=your_key_here`.

5.  **Run the Application**

    ```bash
    python app.py
    ```

6.  **Access the Dashboard**

      * Open your browser and navigate to `http://127.0.0.1:5000/dashboard`.

-----

## 🧪 Testing the System

You can test PhishShield using:

  * **EICAR test file:** A safe, standard test file for antivirus software.
  * **Damn Vulnerable Web Application (DVWA):** Use it to simulate various file upload and injection attacks.
  * **Malicious URL Lists:** Use resources like PhishTank or VirusTotal's public samples to test URL detection.
  * **Kali Linux:** For controlled penetration testing to validate the system's defenses.

-----

## 👥 Team Roles

  * **Ruth Yeshitila:** Core Logic & URL/File Scanning
  * **Member 2:** Flask Routing & Middleware Development
  * **Member 3:** Dashboard UI & Logging System
  * **Member 4:** Testing, Documentation & Reporting

-----

## 🚀 Future Improvements

  * Integrate a **Machine Learning model** for zero-day phishing detection.
  * Add **real-time email scanning** functionality.
  * Implement **cloud deployment** using Docker for enhanced scalability.
  * Develop a **multi-language dashboard** to support a wider user base.

-----

## 📜 License

This project is licensed under the **MIT License**—free for personal and educational use.

-----

## 📧 Contact

For inquiries or contributions, please contact:

  * **Email:** ruthye64@example.com
  * **GitHub:** ruye19
  * **Telegram** @noirHazel

-----
