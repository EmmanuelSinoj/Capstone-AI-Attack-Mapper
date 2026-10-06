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

v3 additions (all additive):
    Pilot / repeat runs            ->  save_mapper_result()    (one row per run, nothing overwritten)
    Loading the full answer key    ->  save_answer_key()       (or load_answer_key.py)
    Dev / held-out split           ->  assign_splits()         (or assign_split.py)
    Scoring                        ->  the mapper_scores and evaluation_truth views
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
import random

DB_PATH = Path(__file__).parent / "alerts.db"
# Bump when a VIEW definition in schema.sql changes: `CREATE VIEW IF NOT EXISTS` never replaces
# an existing view, so ensure_schema() re-creates the views whenever the database is older.
SCHEMA_VERSION = 3
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
    "predicted_category": "TEXT",
    "classified_at": "TEXT",
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
    "predicted_category", "classified_at", "lifecycle_phase", "attck_technique", "atlas_technique", "owasp_category",
    "classification_confidence", "rationale", "sub_cluster", "in_scope",
    "adversarial", "system_prompt_version", "probe_id", "run_id",
    "hardening_applied", "playbook", "attack_succeeded", "timestamp",
]


def migrate_missing_columns(conn: sqlite3.Connection) -> bool:
    """Add any column from MIGRATION_COLUMNS that the alerts table lacks. Safe to repeat.
    Returns True if this call found missing columns (so the caller can refresh the views)."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    added = False
    for name, definition in MIGRATION_COLUMNS.items():
        if name not in existing:
            added = True
            try:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
            except sqlite3.OperationalError as exc:
                # Another request/thread added the same column between our check and our ALTER
                # (the testbed logs from several threads right after a restart). That's fine.
                if "duplicate column name" not in str(exc):
                    raise
    conn.commit()
    return added


def _refresh_views(conn: sqlite3.Connection, script: str) -> None:
    """Recreate the two views from schema.sql. `CREATE VIEW IF NOT EXISTS` never replaces an
    existing view, so a database that already holds an older definition (for example the
    evaluation view that read the detector's flag as the Mapper's answer) must drop them first."""
    conn.executescript("DROP VIEW IF EXISTS mapper_input;\nDROP VIEW IF EXISTS evaluation_truth;\n"
                       "DROP VIEW IF EXISTS mapper_scores;\n" + script)


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
    added = False
    try:
        conn.executescript(script)
    except sqlite3.OperationalError:
        added = migrate_missing_columns(conn)
        conn.executescript(script)
    stale_views = conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION
    if migrate_missing_columns(conn) or added or stale_views:
        _refresh_views(conn, script)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


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

    The Mapper's category goes to predicted_category and its confidence to
    classification_confidence. The detector's own columns (`category`, the live flag,
    and `confidence`) are left untouched. classified_at records that the Mapper has
    run, even when it answered "out of scope". Framework id lists are stored as JSON text.
    """
    mapping = result.get("framework_mapping") or {}
    update_alert(
        conn, alert_id,
        predicted_category=result.get("category"),
        classified_at=datetime.now(timezone.utc).isoformat(),
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


def get_mapper_queue(conn: sqlite3.Connection, source: Optional[str] = None,
                     limit: Optional[int] = None) -> list:
    """Ids of alerts still waiting for the Mapper: every unclassified synthetic alert,
    and every unclassified live alert the detector flagged (category is set)."""
    query = ("SELECT id FROM alerts WHERE classified_at IS NULL "
             "AND (source = 'synthetic' OR category IS NOT NULL)")
    params: list = []
    if source is not None:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY id"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
    return [r["id"] for r in conn.execute(query, params)]


_LIST_FIELDS_KEY = {"atlas_techniques_supporting": "atlas_supporting", "attck_techniques": "attck_techniques",
                    "owasp_llm_2026": "owasp_categories"}


def _json_list(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value if isinstance(value, (list, tuple)) else [value])


def save_mapper_result(conn: sqlite3.Connection, alert_id: int, run_id: str, model: str,
                       result: Optional[dict] = None, *, raw_output: Optional[str] = None,
                       prompt_version: Optional[str] = None, repeat_no: int = 1,
                       error: Optional[str] = None, latency_ms: Optional[int] = None,
                       input_tokens: Optional[int] = None, output_tokens: Optional[int] = None,
                       update_alert_row: bool = False) -> int:
    """Store ONE Mapper run on ONE alert in mapper_results, leaving other runs untouched.

    `result` is the parsed JSON the Mapper returned (see the prompt's output schema), or None
    when the reply was not valid JSON; keep the reply in `raw_output` either way. A reply with an
    impossible category or confidence is recorded as invalid (valid_json = 0), not rejected,
    so JSON reliability can be measured. Re-saving the same (alert, run_id, repeat_no)
    replaces that row. With update_alert_row=True a valid result is also copied onto the alert's
    own Mapper columns (use that only for the model you finally choose).
    Returns the mapper_results row id.
    """
    if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise ValueError(f"no alert with id {alert_id}")
    valid = isinstance(result, dict)
    r = result if valid else {}
    category, confidence = r.get("category"), r.get("confidence")
    if valid and category is not None and category not in ("A", "B", "C", "D", "E"):
        valid, error = False, error or f"invalid category {category!r}"
    if valid and confidence is not None and not (isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0):
        valid, error = False, error or f"invalid confidence {confidence!r}"
    if not valid:
        r, category, confidence = {}, None, None
    mapping = r.get("framework_mapping") or {}
    conn.execute(
        """INSERT INTO mapper_results
             (alert_id, run_id, model, prompt_version, repeat_no, valid_json, predicted_category, sub_cluster,
              in_scope, adversarial, lifecycle_phase, attck_technique, atlas_technique, owasp_category,
              confidence, rationale, raw_output, error, latency_ms, input_tokens, output_tokens)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(alert_id, run_id, repeat_no) DO UPDATE SET
             model=excluded.model, prompt_version=excluded.prompt_version, valid_json=excluded.valid_json,
             predicted_category=excluded.predicted_category, sub_cluster=excluded.sub_cluster,
             in_scope=excluded.in_scope, adversarial=excluded.adversarial, lifecycle_phase=excluded.lifecycle_phase,
             attck_technique=excluded.attck_technique, atlas_technique=excluded.atlas_technique,
             owasp_category=excluded.owasp_category, confidence=excluded.confidence, rationale=excluded.rationale,
             raw_output=excluded.raw_output, error=excluded.error, latency_ms=excluded.latency_ms,
             input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
             created_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')""",
        (alert_id, run_id, model, prompt_version, repeat_no, int(valid), category,
         r.get("sub_cluster_or_theme"), _flag_or_none(r.get("in_scope")), _flag_or_none(r.get("adversarial")),
         r.get("lifecycle_phase"), _json_or_none(mapping, "attack"), _json_or_none(mapping, "atlas"),
         _json_or_none(mapping, "owasp_llm"), confidence, r.get("rationale"), raw_output, error,
         latency_ms, input_tokens, output_tokens))
    conn.commit()
    row_id = conn.execute("SELECT id FROM mapper_results WHERE alert_id=? AND run_id=? AND repeat_no=?",
                          (alert_id, run_id, repeat_no)).fetchone()[0]
    if update_alert_row and valid:
        save_classification(conn, alert_id, result)
    return row_id


def get_mapper_results(conn: sqlite3.Connection, run_id: Optional[str] = None) -> list:
    """All stored Mapper runs (optionally one run_id), oldest first."""
    if run_id is None:
        rows = conn.execute("SELECT * FROM mapper_results ORDER BY id")
    else:
        rows = conn.execute("SELECT * FROM mapper_results WHERE run_id = ? ORDER BY id", (run_id,))
    return [dict(r) for r in rows]


def save_answer_key(conn: sqlite3.Connection, alert_id: int, key: dict, overwrite: bool = False) -> bool:
    """Store the full answer key for one alert. Accepts the field names of Shadi's
    ground_truth_final.json (phase, atlas_technique_primary, atlas_techniques_supporting,
    attck_techniques, owasp_llm_2026, non_adversarial, outcome_status, label_note) or the table's own.
    An existing key is NOT changed unless overwrite=True. Returns True if a row was written.
    Also fills alerts.ground_truth_category when it is still empty."""
    if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise ValueError(f"no alert with id {alert_id}")
    if conn.execute("SELECT 1 FROM answer_key WHERE alert_id = ?", (alert_id,)).fetchone() and not overwrite:
        return False
    adversarial = key.get("adversarial")
    if adversarial is None and key.get("non_adversarial") is not None:
        adversarial = not key["non_adversarial"]
    vals = (alert_id, key.get("category"), key.get("sub_cluster"),
            key.get("lifecycle_phase", key.get("phase")),
            key.get("atlas_primary", key.get("atlas_technique_primary")),
            _json_list(key.get("atlas_supporting", key.get("atlas_techniques_supporting"))),
            _json_list(key.get("attck_techniques")),
            _json_list(key.get("owasp_categories", key.get("owasp_llm_2026"))),
            _flag_or_none(key.get("in_scope")), _flag_or_none(adversarial),
            key.get("outcome_status"), key.get("case_type"), key.get("split"), key.get("label_note"))
    conn.execute(
        """INSERT INTO answer_key (alert_id, category, sub_cluster, lifecycle_phase, atlas_primary, atlas_supporting,
                                   attck_techniques, owasp_categories, in_scope, adversarial, outcome_status,
                                   case_type, split, label_note)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(alert_id) DO UPDATE SET category=excluded.category, sub_cluster=excluded.sub_cluster,
             lifecycle_phase=excluded.lifecycle_phase, atlas_primary=excluded.atlas_primary,
             atlas_supporting=excluded.atlas_supporting, attck_techniques=excluded.attck_techniques,
             owasp_categories=excluded.owasp_categories, in_scope=excluded.in_scope,
             adversarial=excluded.adversarial, outcome_status=excluded.outcome_status,
             case_type=excluded.case_type, split=COALESCE(excluded.split, answer_key.split),
             label_note=excluded.label_note""", vals)
    conn.commit()
    if key.get("category") and conn.execute("SELECT ground_truth_category FROM alerts WHERE id = ?",
                                            (alert_id,)).fetchone()[0] is None:
        update_alert(conn, alert_id, allow_protected=True, ground_truth_category=key["category"])
    return True


def assign_splits(conn: sqlite3.Connection, seed: int = 42, dev_fraction: float = 0.4,
                  force: bool = False) -> dict:
    """Assign every answer-key row to 'dev' or 'heldout', stratified by category and reproducible
    from the seed. Refuses to run if any split is already assigned (re-drawing after seeing results
    would defeat the purpose) unless force=True. A category with one alert goes to 'heldout'.
    Returns {category: (n_dev, n_heldout)}."""
    if not force and conn.execute("SELECT 1 FROM answer_key WHERE split IS NOT NULL").fetchone():
        raise ValueError("splits are already assigned; pass force=True to redraw them")
    rows = conn.execute("SELECT alert_id, category FROM answer_key ORDER BY category, alert_id").fetchall()
    by_cat: dict = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r["alert_id"])
    rng = random.Random(seed)
    summary = {}
    for cat in sorted(by_cat, key=lambda c: (c is None, c)):
        ids = by_cat[cat][:]
        rng.shuffle(ids)
        n = len(ids)
        n_dev = 0 if n < 2 else min(n - 1, max(1, round(dev_fraction * n)))
        for i, aid in enumerate(ids):
            conn.execute("UPDATE answer_key SET split = ? WHERE alert_id = ?", ("dev" if i < n_dev else "heldout", aid))
        summary[cat] = (n_dev, n - n_dev)
    conn.commit()
    return summary


def get_ground_truth(conn: sqlite3.Connection) -> list:
    """For evaluation scripts: the answer key next to the Mapper's prediction,
    for every alert that has a ground-truth label."""
    return [dict(r) for r in conn.execute("SELECT * FROM evaluation_truth ORDER BY id")]


if __name__ == "__main__":
    # Running this file directly just (re)creates/upgrades the schema so the
    # team can inspect alerts.db with any SQLite browser during dev.
    get_connection().close()
    print(f"Alert store ready at {DB_PATH}")
