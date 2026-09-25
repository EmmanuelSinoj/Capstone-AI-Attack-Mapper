"""
Minimal SQLite helper for the shared Alert Store.

Every component (detection, synthetic generator, classification engine,
evaluation) should go through `get_connection()` / `insert_alert()` /
`update_alert()` rather than opening the .db file directly, so the schema
stays the single source of truth for what an "alert" looks like.
"""

import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "alerts.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text())
    return conn


def insert_alert(conn: sqlite3.Connection, **fields: Any) -> int:
    """Insert a new alert row. `fields` must use column names from schema.sql.

    Example:
        insert_alert(conn, source="live", input="...", output="...",
                     detector="heuristic+llama-guard", confidence=0.92,
                     probe_id="garak.promptinject.01", system_prompt_version=1)
    """
    columns = ", ".join(fields.keys())
    placeholders = ", ".join("?" for _ in fields)
    cur = conn.execute(
        f"INSERT INTO alerts ({columns}) VALUES ({placeholders})",
        tuple(fields.values()),
    )
    conn.commit()
    return cur.lastrowid


def update_alert(conn: sqlite3.Connection, alert_id: int, **fields: Any) -> None:
    """Patch an existing alert row (e.g. attach classification results)."""
    assignments = ", ".join(f"{k} = ?" for k in fields.keys())
    conn.execute(
        f"UPDATE alerts SET {assignments} WHERE id = ?",
        (*fields.values(), alert_id),
    )
    conn.commit()


if __name__ == "__main__":
    # Running this file directly just (re)creates the schema so the
    # team can inspect alerts.db with any SQLite browser during dev.
    get_connection().close()
    print(f"Alert store ready at {DB_PATH}")
