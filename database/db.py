"""SQLite Database operations and connection management for FORENSIX.

All operations use parameterized queries to avoid injection vulnerabilities.
Provides automatic schema initialization, schema migration, transaction integrity,
and explicit connection lifetime management to prevent connection leaks.
"""
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from config import DB_PATH, SCHEMA_PATH

logger = logging.getLogger(__name__)


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Creates and returns a connection to SQLite with row factory set to sqlite3.Row."""
    target_path = str(db_path or DB_PATH)
    conn = sqlite3.connect(target_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Safely runs backward-compatible migrations for existing databases."""
    cursor = conn.cursor()

    # Check columns in evidence table
    cursor.execute("PRAGMA table_info(evidence);")
    ev_cols = [row["name"] for row in cursor.fetchall()]
    if ev_cols and "mime_type" not in ev_cols:
        cursor.execute("ALTER TABLE evidence ADD COLUMN mime_type TEXT;")

    # Check columns in custody_events table
    cursor.execute("PRAGMA table_info(custody_events);")
    coc_cols = [row["name"] for row in cursor.fetchall()]
    if coc_cols:
        if "previous_event_hash" not in coc_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN previous_event_hash TEXT;")
        if "current_event_hash" not in coc_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN current_event_hash TEXT;")


def init_db(db_path: Optional[Path] = None, schema_path: Optional[Path] = None) -> None:
    """Initializes the database schema if tables do not exist and runs safe migrations."""
    s_path = schema_path or SCHEMA_PATH
    if not s_path.exists():
        raise FileNotFoundError(f"Schema file not found at: {s_path}")

    with open(s_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = get_connection(db_path)
    try:
        conn.executescript(schema_sql)
        _migrate_schema(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    logger.info("Database initialized successfully at %s", db_path or DB_PATH)


def execute_query(query: str, params: tuple = (), db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Executes a read query with parameters and returns a list of dictionaries."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def execute_commit(query: str, params: tuple = (), db_path: Optional[Path] = None) -> int:
    """Executes an INSERT, UPDATE, or DELETE query and returns the affected row count."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_many(query: str, param_list: List[tuple], db_path: Optional[Path] = None) -> int:
    """Executes a parameterized query across multiple parameter tuples in a single transaction."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.executemany(query, param_list)
        conn.commit()
        return cursor.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
