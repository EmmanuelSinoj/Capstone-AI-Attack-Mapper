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

# Columns added to schema.sql after alerts.db may already have been
# created on a teammate's machine. `CREATE TABLE IF NOT EXISTS` in
# schema.sql does NOT retroactively add columns to an existing table --
# SQLite just skips the whole statement -- so a self-heal migration runs
# here on every connect. Safe to run repeatedly: it only ALTERs a column
# in if it's missing.
_MIGRATION_COLUMNS = {
    # Kept as plain types (no CHECK) here -- SQLite's ALTER TABLE ADD
    # COLUMN has restrictions around constraints on existing tables, and
    # the CHECK in schema.sql's CREATE TABLE already covers brand-new
    # databases. Application code is responsible for only ever writing
    # 0/1/NULL into attack_succeeded.
    "run_id": "TEXT",
    "attack_succeeded": "INTEGER",
}


def _migrate_missing_columns(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    for name, coltype in _MIGRATION_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {coltype}")
    conn.commit()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA_PATH.read_text())
    except sqlite3.OperationalError:
        # A pre-existing alerts.db predates a column schema.sql's own
        # CREATE INDEX statements now reference (e.g. run_id) -- the
        # CREATE TABLE IF NOT EXISTS above was a no-op against the old
        # table, so the later CREATE INDEX ... ON alerts(run_id) fails
        # with "no such column". Migrate the missing columns in, then
        # replay the (idempotent) script so its indexes succeed.
        _migrate_missing_columns(conn)
        conn.executescript(SCHEMA_PATH.read_text())
    _migrate_missing_columns(conn)
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
