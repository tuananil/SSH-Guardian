"""
database.py
-----------
SQLite tabanlı KALICILIK katmanı.

Amaç:
- Her log analiz oturumunu (session) ve içindeki saldırgan IP'leri saklamak.
- Geçmiş analizleri "History" sekmesinden tekrar görüntüleyebilmek.

Şema:
    sessions:
        id            INTEGER PRIMARY KEY
        source_file   TEXT
        created_at    TEXT   (ISO datetime)
        total_events  INTEGER
        total_failed  INTEGER
        total_success INTEGER
        suspicious    INTEGER

    attackers:
        id            INTEGER PRIMARY KEY
        session_id    INTEGER FK -> sessions(id)
        ip            TEXT
        failed        INTEGER
        successful    INTEGER
        risk          TEXT
        country       TEXT
        first_seen    TEXT
        last_seen     TEXT
"""

import os
import sqlite3
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

from analyzer.detector import AnalysisResult
from utils.constants import DB_PATH


# ----------------------------------------------------------------------
# Kayıtlı oturum özeti (history list için)
# ----------------------------------------------------------------------
@dataclass
class SessionSummary:
    id: int
    source_file: str
    created_at: str
    total_events: int
    total_failed: int
    suspicious: int


# ----------------------------------------------------------------------
# DB sınıfı
# ----------------------------------------------------------------------
class HistoryDB:
    """SQLite üzerine ince bir DAL (Data Access Layer)."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or DB_PATH
        # check_same_thread=False -> watcher thread/main thread aynı conn'u
        # kullanabilsin. Yazma işlemleri tek thread'den yapılır.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------
    def _init_schema(self) -> None:
        c = self._conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file   TEXT,
                created_at    TEXT,
                total_events  INTEGER,
                total_failed  INTEGER,
                total_success INTEGER,
                suspicious    INTEGER
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS attackers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  INTEGER NOT NULL,
                ip          TEXT,
                failed      INTEGER,
                successful  INTEGER,
                risk        TEXT,
                country     TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    def save_session(self, source_file: str, result: AnalysisResult) -> int:
        """
        Bir AnalysisResult'ı veritabanına kaydeder.
        Yeni session_id döner.
        """
        c = self._conn.cursor()
        c.execute(
            """
            INSERT INTO sessions
                (source_file, created_at, total_events, total_failed,
                 total_success, suspicious)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                os.path.basename(source_file),
                datetime.now().isoformat(timespec="seconds"),
                result.total_events,
                result.total_failed,
                result.total_success,
                result.suspicious_count,
            ),
        )
        session_id = c.lastrowid

        # Bulk insert
        rows = [
            (
                session_id,
                a.ip,
                a.failed_attempts,
                a.successful_logins,
                a.risk_level,
                a.country,
                a.first_seen.isoformat() if a.first_seen else None,
                a.last_seen.isoformat() if a.last_seen else None,
            )
            for a in result.attackers
        ]
        c.executemany(
            """
            INSERT INTO attackers
                (session_id, ip, failed, successful, risk, country,
                 first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._conn.commit()
        return session_id

    # ------------------------------------------------------------------
    def list_sessions(self) -> list[SessionSummary]:
        """Tüm oturumları en yeniden eskiye listeler."""
        c = self._conn.cursor()
        c.execute(
            "SELECT id, source_file, created_at, total_events, "
            "total_failed, suspicious FROM sessions ORDER BY id DESC"
        )
        return [
            SessionSummary(
                id=r["id"],
                source_file=r["source_file"],
                created_at=r["created_at"],
                total_events=r["total_events"],
                total_failed=r["total_failed"],
                suspicious=r["suspicious"],
            )
            for r in c.fetchall()
        ]

    # ------------------------------------------------------------------
    def get_session_attackers(self, session_id: int) -> list[dict]:
        """Bir oturumun saldırgan satırlarını döner (dashboard tarzı tablo için)."""
        c = self._conn.cursor()
        c.execute(
            "SELECT ip, failed, successful, risk, country, first_seen, last_seen "
            "FROM attackers WHERE session_id = ? ORDER BY failed DESC",
            (session_id,),
        )
        return [dict(r) for r in c.fetchall()]

    # ------------------------------------------------------------------
    def delete_session(self, session_id: int) -> None:
        c = self._conn.cursor()
        c.execute("DELETE FROM attackers WHERE session_id = ?", (session_id,))
        c.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        self._conn.commit()

    # ------------------------------------------------------------------
    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
