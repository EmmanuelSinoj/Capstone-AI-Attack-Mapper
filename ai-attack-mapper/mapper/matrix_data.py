"""
mapper/matrix_data.py

Data behind the dashboard's visual ATT&CK / ATLAS matrix: tactic columns,
technique rows (sub-techniques nested under their parent, as on
attack.mitre.org / atlas.mitre.org), each technique colored by the highest
severity among the classified alerts that mapped to it.

Two sources of "classified alerts":
  - run_id=None: the alert rows themselves (what the production pipeline
    saved with db.save_classification(): classified_at set).
  - run_id="...": one Model Selection Pilot run in mapper_results (repeat 1,
    valid replies only), so a pilot run's mapping can be inspected the same way.

The shared alert store has no severity column; severity is deterministic
(severity.py), so it's recomputed here from category / sub-cluster /
adversarial / confidence.

Tactic structure comes from data/framework_reference_data.json
(attack_tactics, atlas_tactics, *_technique_tactics), built by
build_framework_reference.py from ATT&CK v20 and ATLAS 2026.09.
"""

import re
from collections import defaultdict

from . import framework_reference as fw_ref
from .severity import LEVELS as SEVERITY_LEVELS, severity_from_fields

_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_LEVELS)}

SEVERITY_COLORS = {
    "Critical": "#b71c1c",
    "High": "#e65100",
    "Medium": "#f9a825",
    "Low": "#2e7d32",
    "Informational": "#546e7a",
    None: "#e0e0e0",  # no alert has touched this technique/risk yet
}

_ID_SPLIT_RE = re.compile(r"^(.*)\.(\d+)$")  # "T1055.011" -> ("T1055", "011")

_FW_COLUMNS = {"attack": "attck_technique", "atlas": "atlas_technique", "owasp_llm": "owasp_category"}


def _parent_id(technique_id: str) -> str | None:
    m = _ID_SPLIT_RE.match(technique_id)
    return m.group(1) if m else None


def classified_rows(conn, run_id: str | None = None) -> list[dict]:
    """[{alert_id, severity, attack: [...], atlas: [...], owasp_llm: [...]}] for every
    classified, in-scope alert (or every valid repeat-1 reply of one pilot run)."""
    if run_id is None:
        rows = conn.execute(
            "SELECT id AS alert_id, predicted_category AS category, sub_cluster, adversarial, "
            "classification_confidence AS confidence, in_scope, attck_technique, atlas_technique, owasp_category "
            "FROM alerts WHERE classified_at IS NOT NULL"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT alert_id, predicted_category AS category, sub_cluster, adversarial, confidence, in_scope, "
            "attck_technique, atlas_technique, owasp_category FROM mapper_results "
            "WHERE run_id = ? AND repeat_no = 1 AND valid_json = 1", (run_id,)
        ).fetchall()
    out = []
    for r in rows:
        in_scope = r["in_scope"]
        if in_scope == 0:
            continue
        sev = severity_from_fields(r["category"], r["sub_cluster"], r["adversarial"], r["confidence"],
                                   in_scope=1 if in_scope is None else in_scope)["severity"]
        item = {"alert_id": r["alert_id"], "severity": sev}
        for fw, col in _FW_COLUMNS.items():
            item[fw] = fw_ref.parse_id_list(r[col])
        out.append(item)
    return out


def _hits(rows: list[dict], framework: str) -> dict:
    """{resolved technique id: [(alert_id, severity), ...]}. IDs that don't resolve against
    the real data are skipped here (the dashboard's 'unresolved' panel reports them)."""
    hits = defaultdict(list)
    for row in rows:
        for raw_id in row[framework]:
            resolved = fw_ref.lookup(framework, raw_id)
            if resolved.resolved:
                hits[resolved.id].append((row["alert_id"], row["severity"]))
    return hits


def _worst_severity(entries: list) -> str | None:
    ranked = [sev for _, sev in entries if sev in _SEVERITY_RANK]
    return max(ranked, key=lambda s: _SEVERITY_RANK[s]) if ranked else None


def build_matrix(conn, framework: str, run_id: str | None = None) -> dict:
    """framework: "attack" | "atlas". Returns {"tactics": [...], "columns": {tactic_id: [row, ...]},
    "tactic_hits": {tactic_id: severity}} where row = {id, name, url, severity, alert_ids,
    subtechniques, child_severity}. child_severity is the worst severity among the row's
    sub-techniques, so a parent whose only hits are on sub-techniques can still be marked."""
    data = fw_ref._load()
    id_table = data[framework]
    tactics = data[f"{framework}_tactics"]
    technique_tactics = data[f"{framework}_technique_tactics"]
    hits = _hits(classified_rows(conn, run_id), framework)

    def make_row(tid: str) -> dict:
        entries = hits.get(tid, [])
        return {"id": tid, "name": id_table.get(tid, {}).get("name", tid),
                "url": id_table.get(tid, {}).get("url", ""), "severity": _worst_severity(entries),
                "alert_ids": sorted({a for a, _ in entries}), "subtechniques": [], "child_severity": None}

    rows_by_id = {tid: make_row(tid) for tid in id_table if tid in technique_tactics}
    top_level_by_tactic = defaultdict(list)
    for tid, row in rows_by_id.items():
        parent = _parent_id(tid)
        if parent and parent in rows_by_id:
            rows_by_id[parent]["subtechniques"].append(row)
            continue
        for tac_id in technique_tactics.get(tid, []):
            top_level_by_tactic[tac_id].append(row)

    for rows in top_level_by_tactic.values():
        rows.sort(key=lambda r: r["name"])
        for row in rows:
            row["subtechniques"].sort(key=lambda r: r["name"])
            child = [(None, s["severity"]) for s in row["subtechniques"] if s["severity"]]
            row["child_severity"] = _worst_severity(child)

    # Tactic IDs (e.g. TA0043 for Category A) are valid answers but have no cell of their own;
    # the renderer highlights the column header instead.
    tactic_hits = {t["id"]: _worst_severity(hits[t["id"]]) for t in tactics if t["id"] in hits}
    return {"tactics": tactics, "columns": dict(top_level_by_tactic), "tactic_hits": tactic_hits}


def build_owasp_strip(conn, run_id: str | None = None) -> list:
    """OWASP LLM Top 10 has no tactic grid: one severity-colored card per risk."""
    id_table = fw_ref._load()["owasp_llm"]
    hits = _hits(classified_rows(conn, run_id), "owasp_llm")
    out = []
    for llm_id in sorted(id_table, key=lambda k: int(k[3:])):
        entries = hits.get(llm_id, [])
        out.append({"id": llm_id, "name": id_table[llm_id]["name"], "url": id_table[llm_id]["url"],
                    "severity": _worst_severity(entries), "alert_ids": sorted({a for a, _ in entries})})
    return out
