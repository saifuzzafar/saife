"""
Memory Store — SQLite Persistent Memory
=========================================
Stores scan history, conversations, and user preferences.
All text is PII-sanitized before storage via the guardrail.

Tables:
  - scan_history: target, category, score, grade, findings, timestamp
  - conversations: query, response, timestamp
  - preferences: key-value settings
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

from nodes.pii_guardrail import sanitize


# ── Configuration ─────────────────────────────────────────────────

DB_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "saife_memory.db"


# ── Data Models ───────────────────────────────────────────────────

@dataclass
class ScanRecord:
    """A historical scan record."""
    id: int
    target_url: str
    categories: str
    score: int
    grade: str
    findings_count: int
    findings_summary: str
    timestamp: str

    @property
    def datetime(self) -> datetime:
        return datetime.fromisoformat(self.timestamp)


@dataclass
class ConversationRecord:
    """A stored conversation exchange."""
    id: int
    query: str
    response: str
    agent: str
    timestamp: str


# ── Memory Store ──────────────────────────────────────────────────

class MemoryStore:
    """SQLite-backed persistent memory for SAIFE."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or str(DB_PATH)
        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    findings_summary TEXT DEFAULT '',
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    response TEXT NOT NULL,
                    agent TEXT DEFAULT 'scanner',
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_target
                    ON scan_history(target_url);

                CREATE INDEX IF NOT EXISTS idx_scan_timestamp
                    ON scan_history(timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_conv_timestamp
                    ON conversations(timestamp DESC);
            """)

    def _connect(self) -> sqlite3.Connection:
        """Create a database connection."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Scan History ──────────────────────────────────────────────

    def save_scan(
        self,
        target_url: str,
        categories: list[str],
        score: int,
        grade: str,
        findings_count: int,
        findings_summary: str = "",
    ) -> int:
        """Save a scan result to history. PII is stripped before storage.

        Returns the ID of the inserted record.
        """
        # Sanitize all text fields
        safe_url = sanitize(target_url)
        safe_summary = sanitize(findings_summary)
        safe_categories = ",".join(categories)
        timestamp = datetime.now().isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO scan_history
                   (target_url, categories, score, grade, findings_count,
                    findings_summary, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (safe_url, safe_categories, score, grade, findings_count,
                 safe_summary, timestamp),
            )
            return cursor.lastrowid

    def get_history(
        self,
        target_url: str | None = None,
        limit: int = 20,
    ) -> list[ScanRecord]:
        """Get scan history, optionally filtered by target URL."""
        with self._connect() as conn:
            if target_url:
                rows = conn.execute(
                    """SELECT * FROM scan_history
                       WHERE target_url LIKE ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (f"%{target_url}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM scan_history
                       ORDER BY timestamp DESC LIMIT ?""",
                    (limit,),
                ).fetchall()

        return [
            ScanRecord(
                id=row["id"],
                target_url=row["target_url"],
                categories=row["categories"],
                score=row["score"],
                grade=row["grade"],
                findings_count=row["findings_count"],
                findings_summary=row["findings_summary"],
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

    # ── Conversations ─────────────────────────────────────────────

    def save_conversation(
        self,
        query: str,
        response: str,
        agent: str = "scanner",
    ) -> int:
        """Save a conversation exchange. PII is stripped."""
        safe_query = sanitize(query)
        safe_response = sanitize(response)
        timestamp = datetime.now().isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO conversations (query, response, agent, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (safe_query, safe_response, agent, timestamp),
            )
            return cursor.lastrowid

    def get_conversations(
        self,
        limit: int = 10,
        agent: str | None = None,
    ) -> list[ConversationRecord]:
        """Get recent conversations."""
        with self._connect() as conn:
            if agent:
                rows = conn.execute(
                    """SELECT * FROM conversations
                       WHERE agent = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (agent, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM conversations
                       ORDER BY timestamp DESC LIMIT ?""",
                    (limit,),
                ).fetchall()

        return [
            ConversationRecord(
                id=row["id"],
                query=row["query"],
                response=row["response"],
                agent=row["agent"],
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

    # ── Preferences ───────────────────────────────────────────────

    def set_preference(self, key: str, value: str) -> None:
        """Set a user preference (upsert)."""
        timestamp = datetime.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO preferences (key, value, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key)
                   DO UPDATE SET value = excluded.value,
                                 updated_at = excluded.updated_at""",
                (key, value, timestamp),
            )

    def get_preference(self, key: str, default: str = "") -> str:
        """Get a user preference."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM preferences WHERE key = ?",
                (key,),
            ).fetchone()
        return row["value"] if row else default

    def clear_history(self) -> None:
        """Delete all scan history records."""
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history")

    # ── Stats ─────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get overall usage statistics."""
        with self._connect() as conn:
            scan_count = conn.execute(
                "SELECT COUNT(*) as c FROM scan_history"
            ).fetchone()["c"]
            conv_count = conn.execute(
                "SELECT COUNT(*) as c FROM conversations"
            ).fetchone()["c"]
            avg_score = conn.execute(
                "SELECT AVG(score) as avg FROM scan_history"
            ).fetchone()["avg"]

        return {
            "total_scans": scan_count,
            "total_conversations": conv_count,
            "average_score": round(avg_score, 1) if avg_score else 0,
        }


# ── Module-level singleton ────────────────────────────────────────

_store: MemoryStore | None = None


def get_memory() -> MemoryStore:
    """Get or create the singleton memory store."""
    global _store
    if _store is None:
        _store = MemoryStore()
    return _store
