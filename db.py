import sqlite3
import os
from typing import List, Dict

DB_FILE = os.path.join(os.path.dirname(__file__), "ethioscan.db")

def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            scan_time TEXT,
            depth INTEGER,
            concurrency INTEGER,
            max_tests INTEGER,
            lab_mode INTEGER,
            total_findings INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id INTEGER,
            url TEXT,
            param TEXT,
            payload TEXT,
            category TEXT,
            severity TEXT,
            evidence TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    conn.close()

def save_scan(scan_info: Dict) -> int:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (target_url, scan_time, depth, concurrency, max_tests, lab_mode, total_findings)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_info.get("target_url"),
        scan_info.get("scan_time"),
        scan_info.get("depth"),
        scan_info.get("concurrency"),
        scan_info.get("max_tests"),
        int(scan_info.get("lab_mode", False)),
        scan_info.get("total_findings", 0)
    ))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def save_findings(scan_id: int, findings: List[Dict]):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in findings:
        c.execute("""
            INSERT OR REPLACE INTO findings (id, scan_id, url, param, payload, category, severity, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f.get("id"),
            scan_id,
            f.get("url"),
            f.get("param"),
            f.get("payload", {}).get("payload"),
            f.get("category"),
            f.get("severity"),
            f.get("evidence")
        ))
    conn.commit()
    conn.close()
