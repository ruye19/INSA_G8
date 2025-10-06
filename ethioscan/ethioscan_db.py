# ethioscan_db.py
from __future__ import annotations
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from sqlalchemy import (
    create_engine, Integer, String, Text, DateTime, Boolean, ForeignKey, Index, update
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.types import JSON

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ethioscan.db")
DB_ENABLED   = os.getenv("DB_ENABLED", "true").lower() == "true"

# SQLite pragmas for better behavior
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}  # allow use inside threads if needed

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    depth: Mapped[Optional[int]] = mapped_column(Integer)
    concurrency: Mapped[Optional[int]] = mapped_column(Integer)
    max_tests: Mapped[Optional[int]] = mapped_column(Integer)
    lab_mode: Mapped[Optional[bool]] = mapped_column(Boolean)

    tests_executed: Mapped[Optional[int]] = mapped_column(Integer)
    total_findings: Mapped[Optional[int]] = mapped_column(Integer)

    report_html_path: Mapped[Optional[str]] = mapped_column(Text)
    report_json_path: Mapped[Optional[str]] = mapped_column(Text)

    findings: Mapped[List["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # use your UUID
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    category: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    url: Mapped[Optional[str]] = mapped_column(Text)
    param: Mapped[Optional[str]] = mapped_column(String(256))
    payload: Mapped[Optional[dict]] = mapped_column(JSON)  # works on SQLite (as TEXT) & Postgres (as JSON/JSONB)
    status: Mapped[Optional[int]] = mapped_column(Integer)
    evidence: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(16), index=True)
    timestamp: Mapped[Optional[str]] = mapped_column(String(64))

    scan: Mapped[Scan] = relationship(back_populates="findings")

# Helpful composite index for common lookups
Index("ix_findings_scan_severity", Finding.scan_id, Finding.severity)

def init_db() -> None:
    if not DB_ENABLED:
        return
    Base.metadata.create_all(engine)

def start_scan(meta: Dict[str, Any]) -> Optional[int]:
    if not DB_ENABLED:
        return None
    from sqlalchemy.orm import Session
    with Session(engine, future=True) as s, s.begin():
        scan = Scan(
            target_url=meta.get("target_url") or meta.get("url") or "unknown",
            depth=meta.get("depth"),
            concurrency=meta.get("concurrency"),
            max_tests=meta.get("max_tests"),
            lab_mode=bool(meta.get("lab_mode", False)),
            tests_executed=meta.get("tests_run") or meta.get("tests_executed"),
        )
        s.add(scan)
        s.flush()
        return scan.id

def save_findings(scan_id: Optional[int], items: List[Dict[str, Any]]) -> None:
    if not DB_ENABLED or not scan_id or not items:
        return
    from sqlalchemy.orm import Session
    rows = []
    for f in items:
        rows.append(Finding(
            id=str(f.get("id") or f.get("uuid") or f"{scan_id}:{len(rows)+1}"),
            scan_id=scan_id,
            category=f.get("category"),
            url=f.get("url"),
            param=f.get("param"),
            payload=f.get("payload"),
            status=f.get("status"),
            evidence=f.get("evidence"),
            severity=f.get("severity"),
            timestamp=f.get("timestamp"),
        ))
    with Session(engine, future=True) as s, s.begin():
        s.add_all(rows)

def finish_scan(scan_id: Optional[int], summary: Dict[str, Any], report_paths: Dict[str, str]) -> None:
    if not DB_ENABLED or not scan_id:
        return
    from sqlalchemy.orm import Session
    with Session(engine, future=True) as s, s.begin():
        s.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                finished_at=datetime.utcnow(),
                total_findings=summary.get("total"),
                tests_executed=summary.get("tests_executed") or summary.get("tests_run"),
                report_html_path=report_paths.get("html"),
                report_json_path=report_paths.get("json"),
            )
        )
