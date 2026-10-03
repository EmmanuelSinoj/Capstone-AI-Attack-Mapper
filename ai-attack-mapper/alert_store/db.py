"""
Minimal SQLite helper for the shared Alert Store.

Every component (detection, synthetic generator, classification engine,
evaluation) should go through this module (or alert_store.py, which is a
thin wrapper over it) rather than opening the .db file directly, so
schema.sql stays the single source of truth for what an "alert" looks like.

Who reads what:
    Mapper / Model Selection Pilot ->  get_mapper_input()      (interaction only)
    Mapper output                  ->  save_classification()   (Mapper's own columns)
    Evaluation scripts             ->  get_ground_truth()      (answer key + prediction)
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

DB_PATH = Path(__file__).parent / "alerts.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Every column except the original base fields, with the plain definition used
# by ALTER TABLE ADD COLUMN. `CREATE TABLE IF NOT EXISTS` in schema.sql does NOT
# retroactively add columns to an existing alerts.db -- SQLite just skips the
# statement -- so ensure_schema() adds whatever is missing. No CHECK constraints
# here (SQLite restricts them on ALTER); those only apply to databases created
# fresh from schema.sql, so rebuild an old alerts.db to get them. The one
# NOT NULL column carries a constant default, which ALTER allows.
MIGRATION_COLUMNS = {
    "lifecycle_phase": "TEXT",
    "attck_technique": "TEXT",
    "atlas_technique": "TEXT",
    "owasp_category": "TEXT",
    "classification_confidence": "REAL",
    "rationale": "TEXT",
    "sub_cluster": "TEXT",
    "in_scope": "INTEGER",
    "adversarial": "INTEGER",
    "probe_id": "TEXT",
    "run_id": "TEXT",
    "source_reference": "TEXT",
    "hardening_applied": "INTEGER NOT NULL DEFAULT 0",
    "playbook": "TEXT",
    "ground_truth_category": "TEXT",
    "attack_succeeded": "INTEGER",
}

# Columns every version of the table has had from the start.
BASE_COLUMNS = ["id", "source", "input", "output", "detector", "confidence",
                "category", "timestamp", "system_prompt_version"]

# Columns that hold the answer key. update_alert() refuses to touch them unless
# you pass allow_protected=True, so a classification run cannot overwrite the
# ground truth by accident.
PROTECTED_COLUMNS = {"ground_truth_category", "source_reference"}

# Everything except the answer key; used by alert_store.query_alerts() by default.
SAFE_ALERT_COLUMNS = [
    "id", "source", "input", "output", "detector", "confidence", "category",
    "lifecycle_phase", "attck_technique", "atlas_technique", "owasp_category",
    "classification_confidence", "rationale", "sub_cluster", "in_scope",
    "adversarial", "system_prompt_version", "probe_id", "run_id",
    "hardening_applied", "playbook", "attack_succeeded", "timestamp",
]


def migrate_missing_columns(conn: sqlite3.Connection) -> None:
    """Add any column from MIGRATION_COLUMNS that the alerts table lacks. Safe to repeat."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    for name, definition in MIGRATION_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
    conn.commit()


def _alerts_table_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone() is not None


def _timestamp_has_default(conn: sqlite3.Connection) -> bool:
    for row in conn.execute("PRAGMA table_info(alerts)"):
        if row[1] == "timestamp":
            return row[4] is not None          # dflt_value
    return True


def _rebuild_alerts_table(conn: sqlite3.Connection) -> None:
    """Rebuild an old-format alerts table from schema.sql, keeping every row.

    Needed for databases created from the old alert_schema.py table: its
    timestamp column is NOT NULL with no default, and SQLite cannot add a default
    to an existing column, so rows without a timestamp (like the synthetic alerts)
    would be rejected. The whole rebuild is one transaction: if anything fails the
    old table is restored untouched.
    """
    old_cols = [r[1] for r in conn.execute("PRAGMA table_info(alerts)")]
    common = ", ".join(c for c in old_cols if c in BASE_COLUMNS + list(MIGRATION_COLUMNS))
    indexes = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alerts' AND sql IS NOT NULL")]
    drops = "\n".join(f'DROP INDEX IF EXISTS "{name}";' for name in indexes)
    script = (
        "BEGIN;\n"
        "DROP VIEW IF EXISTS mapper_input;\n"
        "DROP VIEW IF EXISTS evaluation_truth;\n"
        f"{drops}\n"
        "ALTER TABLE alerts RENAME TO alerts_old;\n"
        f"{SCHEMA_PATH.read_text(encoding='utf-8')}\n"
        f"INSERT INTO alerts ({common}) SELECT {common} FROM alerts_old;\n"
        "DROP TABLE alerts_old;\n"
        "COMMIT;"
    )
    try:
        conn.executescript(script)
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create or upgrade the alerts table, indexes and views from schema.sql.

    * brand-new database: creates everything.
    * old table from the retired alert_schema.py definition (timestamp has no
      default): rebuilt from schema.sql with all rows copied across.
    * older schema.sql-era table: missing columns are added, then the
      (idempotent) script is replayed so indexes and views are created.

    Note: CHECK constraints only exist on tables created fresh from schema.sql.
    """
    if _alerts_table_exists(conn) and not _timestamp_has_default(conn):
        _rebuild_alerts_table(conn)
        return
    script = SCHEMA_PATH.read_text(encoding="utf-8")
    try:
        conn.executescript(script)
    except sqlite3.OperationalError:
        migrate_missing_columns(conn)
        conn.executescript(script)
    migrate_missing_columns(conn)


def get_connection(db_path: Optional[Any] = None) -> sqlite3.Connection:
    """Open the alert store (default: alerts.db next to this file), upgrading it if needed."""
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn


def _check_columns(conn: sqlite3.Connection, names: Iterable[str]) -> None:
    valid = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    unknown = sorted(set(names) - valid)
    if unknown:
        raise ValueError(f"unknown alert column(s): {unknown}. Valid columns: {sorted(valid)}")


def insert_alert(conn: sqlite3.Connection, **fields: Any) -> int:
    """Insert a new alert row. `fields` must use column names from schema.sql.

    Example:
        insert_alert(conn, source="live", input="...", output="...",
                     detector="heuristic+judge", confidence=0.92, category="B",
                     probe_id="garak.promptinject.01", system_prompt_version=1)
    """
    _check_columns(conn, fields)
    columns = ", ".join(fields.keys())
    placeholders = ", ".join("?" for _ in fields)
    cur = conn.execute(
        f"INSERT INTO alerts ({columns}) VALUES ({placeholders})",
        tuple(fields.values()),
    )
    conn.commit()
    return cur.lastrowid


def update_alert(conn: sqlite3.Connection, alert_id: int,
                 allow_protected: bool = False, **fields: Any) -> None:
    """Patch an existing alert row (e.g. attach classification results).

    Refuses to modify the answer-key columns (ground_truth_category,
    source_reference) unless allow_protected=True.
    """
    _check_columns(conn, fields)
    blocked = PROTECTED_COLUMNS & set(fields)
    if blocked and not allow_protected:
        raise ValueError(f"{sorted(blocked)} hold the answer key; pass allow_protected=True to change them")
    assignments = ", ".join(f"{k} = ?" for k in fields.keys())
    conn.execute(
        f"UPDATE alerts SET {assignments} WHERE id = ?",
        (*fields.values(), alert_id),
    )
    conn.commit()


def get_mapper_input(conn: sqlite3.Connection, source: Optional[str] = None,
                     ids: Optional[Iterable[int]] = None,
                     limit: Optional[int] = None) -> list:
    """What the Mapper may see: id, source, input, output -- nothing else.

    Reads the mapper_input view, so the answer key (ground_truth_category,
    source_reference) and any earlier prediction can never leak into the prompt.
    """
    query, params = "SELECT id, source, input, output FROM mapper_input WHERE 1=1", []
    if source is not None:
        query += " AND source = ?"
        params.append(source)
    if ids is not None:
        ids = list(ids)
        query += f" AND id IN ({', '.join('?' for _ in ids)})"
        params.extend(ids)
    query += " ORDER BY id"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
    return [dict(r) for r in conn.execute(query, params)]


def _json_or_none(mapping: dict, key: str) -> Optional[str]:
    return json.dumps(mapping[key]) if key in mapping and mapping[key] is not None else None


def _flag_or_none(value: Any) -> Optional[int]:
    return None if value is None else int(bool(value))


def save_classification(conn: sqlite3.Connection, alert_id: int, result: dict) -> None:
    """Write the Mapper's structured output (see the Mapper prompt's output schema)
    to the alert's own columns.

    The Mapper's confidence goes to classification_confidence; the detector's
    `confidence` is left untouched. Framework id lists are stored as JSON text.
    """
    mapping = result.get("framework_mapping") or {}
    update_alert(
        conn, alert_id,
        category=result.get("category"),
        sub_cluster=result.get("sub_cluster_or_theme"),
        in_scope=_flag_or_none(result.get("in_scope")),
        adversarial=_flag_or_none(result.get("adversarial")),
        lifecycle_phase=result.get("lifecycle_phase"),
        attck_technique=_json_or_none(mapping, "attack"),
        atlas_technique=_json_or_none(mapping, "atlas"),
        owasp_category=_json_or_none(mapping, "owasp_llm"),
        classification_confidence=result.get("confidence"),
        rationale=result.get("rationale"),
    )


def get_ground_truth(conn: sqlite3.Connection) -> list:
    """For evaluation scripts: the answer key next to the Mapper's prediction,
    for every alert that has a ground-truth label."""
    return [dict(r) for r in conn.execute("SELECT * FROM evaluation_truth ORDER BY id")]


if __name__ == "__main__":
    # Running this file directly just (re)creates/upgrades the schema so the
    # team can inspect alerts.db with any SQLite browser during dev.
    get_connection().close()
    print(f"Alert store ready at {DB_PATH}")
