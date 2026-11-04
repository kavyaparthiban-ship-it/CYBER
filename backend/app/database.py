from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DB_PATH = DATA_DIR / "analyses.sqlite3"


@contextmanager
def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize() -> None:
    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                demo INTEGER NOT NULL,
                packet_count INTEGER NOT NULL,
                ike_count INTEGER NOT NULL,
                esp_count INTEGER NOT NULL,
                ah_count INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(analyses)")}
        if "user_id" not in columns:
            connection.execute("ALTER TABLE analyses ADD COLUMN user_id TEXT")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            )
        """)


def create_user(email: str, password_hash: str) -> dict[str, Any] | None:
    user = {
        "id": str(uuid.uuid4()),
        "email": email,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _connect() as connection:
        try:
            connection.execute(
                "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (user["id"], email, password_hash, user["created_at"]),
            )
        except sqlite3.IntegrityError:
            return None
    return user


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    return dict(row) if row else None


def create_auth_session(token_hash: str, user_id: str, expires_at: str) -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (datetime.now(timezone.utc).isoformat(),))
        connection.execute(
            "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )


def get_user_for_session(token_hash: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as connection:
        row = connection.execute(
            """SELECT users.id, users.email, users.created_at
               FROM auth_sessions
               JOIN users ON users.id = auth_sessions.user_id
               WHERE auth_sessions.token_hash = ? AND auth_sessions.expires_at > ?""",
            (token_hash, now),
        ).fetchone()
        if row is None:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
    return dict(row) if row else None


def delete_auth_session(token_hash: str) -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))


def save_analysis(user_id: str, filename: str, demo: bool, result: dict[str, Any]) -> dict[str, Any]:
    analysis_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    row = {
        "id": analysis_id,
        "user_id": user_id,
        "created_at": created_at,
        "filename": filename,
        "demo": demo,
        **result,
    }
    with _connect() as connection:
        connection.execute(
            """INSERT INTO analyses
               (id, user_id, created_at, filename, demo, packet_count, ike_count, esp_count, ah_count,
                risk_score, risk_category, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (analysis_id, user_id, created_at, filename, int(demo), result["capture"]["packet_count"],
             result["capture"]["ike_count"], result["capture"]["esp_count"], result["capture"]["ah_count"],
             result["assessment"]["score"], result["assessment"]["category"], json.dumps(row)),
        )
    return row


def get_analysis(analysis_id: str, user_id: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM analyses WHERE id = ? AND user_id = ?",
            (analysis_id, user_id),
        ).fetchone()
    return json.loads(row["result_json"]) if row else None


def history(user_id: str, limit: int = 50) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT id, created_at, filename, demo, packet_count, ike_count, esp_count, ah_count,
                      risk_score, risk_category
               FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def statistics(user_id: str) -> dict[str, Any]:
    with _connect() as connection:
        row = connection.execute(
            """SELECT COUNT(*) AS analyses, COALESCE(SUM(packet_count), 0) AS packets,
                      COALESCE(SUM(ike_count), 0) AS ike, COALESCE(SUM(esp_count), 0) AS esp,
                      COALESCE(SUM(ah_count), 0) AS ah,
                      COALESCE(SUM(CASE WHEN risk_category IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END), 0) AS elevated
               FROM analyses WHERE user_id = ?""",
            (user_id,),
        ).fetchone()
    return dict(row)
