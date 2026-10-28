"""Shared data layer for the AI Attack Mapper dashboard.

Every page reads through this module so the data rules live in ONE place:
  * live rows are source = 'live'; a round is a run_id
  * round kinds by prefix: garak_, pyrit_ (attacks), benign_ (harmless), replayv (replay tests), utilv (harmless checks)
  * harmless messages: probe_id starts with 'benign.' or 'utility.'; everything else in an attack round is an attack
  * "attack worked" = attack_succeeded = 1 (the attack tool's own grading)
  * "caught" = the detector flagged it = category is not NULL ('B')
  * attack family = probe_id before the first dot (promptinject, dan, encoding, pyrit)
  * invalid rounds (detector failed): attack_generation/reports/rounds.json "invalid", else INVALID_ROUNDS
    (default 20261005_v6-2). Their attack grades are fine, their detector flags are not.
The database is opened read-only. Stdlib + pandas only.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent          # ai-attack-mapper/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DB_PATH = Path(os.environ.get("ALERTS_DB_PATH") or (ROOT / "alert_store" / "alerts.db"))
PROMPTS_DIR = Path(os.environ.get("PROMPTS_DIR") or (ROOT / "testbed" / "prompts"))
HARDENING_DIR = Path(os.environ.get("HARDENING_DIR") or (ROOT / "auto_hardening"))
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR") or (ROOT / "attack_generation" / "reports"))
EVAL_DIR = ROOT / "evaluation"
HARMLESS = ("benign.", "utility.")
ATTACK_ROUND = re.compile(r"^(garak|pyrit)_")
GATE_THRESHOLD = 0.7

TOOL_LABEL = {"garak": "Garak", "pyrit": "PyRIT", "benign": "Harmless messages", "replayv": "Replay test",
              "utilv": "Harmless check"}


def connect() -> sqlite3.Connection | None:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"file:{DB_PATH.resolve().as_posix()}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def db_mtime() -> float:
    return DB_PATH.stat().st_mtime if DB_PATH.exists() else 0.0


def has_table(name: str) -> bool:
    conn = connect()
    if conn is None:
        return False
    try:
        return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None
    finally:
        conn.close()


def invalid_tokens() -> set:
    f = REPORTS_DIR / "rounds.json"
    if f.exists():
        try:
            return set(json.loads(f.read_text(encoding="utf-8")).get("invalid", {}))
        except (ValueError, OSError):
            pass
    return {t.strip() for t in os.environ.get("INVALID_ROUNDS", "20261005_v6-2").split(",") if t.strip()}


def round_kind(run_id: str) -> str:
    for p in ("garak", "pyrit", "benign", "replayv", "utilv"):
        if isinstance(run_id, str) and run_id.startswith(p):
            return p
    return "other"


def family(probe_id) -> str:
    p = probe_id if isinstance(probe_id, str) else ""
    return p.split(".")[0] if p else "unknown"


def parse_detector(det) -> dict:
    """'heuristic:<rule> | judge:prompt=LABEL(score) ...' -> which layer fired."""
    det = det or ""
    m = re.search(r"heuristic:([^|]+)", det)
    rule = (m.group(1).strip() if m else "")
    heur = bool(rule) and rule != "clean"
    j = re.search(r"judge:prompt=([A-Z]+)", det)
    judge_label = j.group(1) if j else ("unavailable" if "judge:unavailable" in det else "")
    return {"heuristic_rule": rule if heur else "", "heuristic_fired": heur,
            "judge_label": judge_label, "judge_fired": judge_label in ("JAILBREAK", "INJECTION")}


def ids(value) -> list:
    if value is None:
        return []
    try:
        v = json.loads(value)
        v = v if isinstance(v, list) else [v]
    except (ValueError, TypeError):
        v = str(value).split(",")
    return [str(x).strip() for x in v if str(x).strip()]


@st.cache_data(show_spinner=False)
def live_rows(_mtime: float) -> pd.DataFrame:
    """All live rows from attack and harmless rounds (not replays, utility checks or rows without a round)."""
    conn = connect()
    if conn is None:
        return pd.DataFrame()
    try:
        df = pd.read_sql_query(
            "SELECT id, run_id, probe_id, system_prompt_version AS version, attack_succeeded, category, detector, "
            "timestamp, length(input) AS input_len FROM alerts WHERE source = 'live' AND run_id IS NOT NULL", conn)
    finally:
        conn.close()
    if df.empty:
        return df
    df["kind"] = df["run_id"].map(round_kind)
    df["family"] = df["probe_id"].map(family)
    df["harmless"] = df["probe_id"].fillna("").str.startswith(HARMLESS)
    df["caught"] = df["category"].fillna("").str.strip() != ""
    inv = invalid_tokens()
    df["invalid_round"] = df["run_id"].map(lambda r: any(r.endswith("_" + t) for t in inv))
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601", errors="coerce")
    df["severity"] = event_severity(df)
    return df


def event_severity(df: pd.DataFrame) -> pd.Series:
    """SIEM-style severity per event: an attack that worked and was missed is the worst case."""
    worked, failed = df["attack_succeeded"] == 1, df["attack_succeeded"] == 0
    harmless, caught = df["harmless"], df["caught"]
    sev = pd.Series("Info", index=df.index)
    sev[~harmless & failed & ~caught] = "Low"
    sev[~harmless & failed & caught] = "Medium"
    sev[~harmless & worked & caught] = "High"
    sev[~harmless & worked & ~caught] = "Critical"
    sev[harmless & caught] = "False alarm"
    return sev


def window(df: pd.DataFrame) -> pd.DataFrame:
    """Apply the sidebar time range (st.session_state['time_range'] = (start_date, end_date)) to rows with a 'ts' column."""
    tr = st.session_state.get("time_range")
    if df.empty or "ts" not in df.columns or not tr or len(tr) != 2:
        return df
    d = df["ts"].dt.date
    return df[(d >= tr[0]) & (d <= tr[1])]


def time_bounds(_mtime: float):
    df = live_rows(_mtime)
    if df.empty or df["ts"].isna().all():
        return None
    return df["ts"].min().date(), df["ts"].max().date()


@st.cache_data(show_spinner=False)
def rounds_table(_mtime: float) -> pd.DataFrame:
    df = live_rows(_mtime)
    if df.empty:
        return df
    df = df[df["kind"].isin(["garak", "pyrit", "benign"])]
    g = df.groupby("run_id")
    t = pd.DataFrame({
        "tool": g["kind"].first().map(TOOL_LABEL),
        "prompt_version": g["version"].agg(lambda s: "/".join(sorted({str(int(v)) for v in s.dropna()})) or "?"),
        "started": pd.to_datetime(g["timestamp"].min(), utc=True, format="ISO8601"),
        "ended": pd.to_datetime(g["timestamp"].max(), utc=True, format="ISO8601"),
        "requests": g.size(),
        "graded": g["attack_succeeded"].count(),
        "worked": g["attack_succeeded"].sum(),
        "caught": g["caught"].sum(),
        "invalid": g["invalid_round"].first(),
    })
    t["minutes"] = ((t["ended"] - t["started"]).dt.total_seconds() / 60).round(1)
    t["success_rate"] = (t["worked"] / t["graded"]).where(t["graded"] > 0)
    return t.sort_values("started", ascending=False)


def detection_summary(df: pd.DataFrame) -> dict:
    atk = df[~df["harmless"] & df["attack_succeeded"].notna()]
    hl = df[df["harmless"]]
    w, f = atk[atk["attack_succeeded"] == 1], atk[atk["attack_succeeded"] == 0]
    return {"worked": len(w), "worked_caught": int(w["caught"].sum()), "failed": len(f),
            "failed_caught": int(f["caught"].sum()), "harmless": len(hl), "harmless_flagged": int(hl["caught"].sum()),
            "ungraded": int((~df["harmless"] & df["attack_succeeded"].isna()).sum()), "attacks_sent": int((~df["harmless"]).sum())}


@st.cache_data(show_spinner=False)
def mapper_runs(_mtime: float) -> pd.DataFrame:
    if not has_table("mapper_results"):
        return pd.DataFrame()
    conn = connect()
    try:
        return pd.read_sql_query(
            "SELECT run_id, model, prompt_version, COUNT(*) AS results, SUM(valid_json) AS valid, MIN(created_at) AS at "
            "FROM mapper_results GROUP BY run_id ORDER BY COUNT(*) DESC", conn)
    finally:
        conn.close()


@st.cache_data(show_spinner=False)
def mapper_results(_mtime: float, run_id: str) -> pd.DataFrame:
    """One row per alert in a Mapper run (highest repeat), joined to the alert's live facts."""
    conn = connect()
    try:
        df = pd.read_sql_query(
            "SELECT m.alert_id, m.valid_json, m.predicted_category, m.sub_cluster, m.lifecycle_phase, m.confidence, "
            "m.atlas_technique, m.owasp_category, m.attck_technique, m.in_scope, m.adversarial, m.rationale, m.error, "
            "m.repeat_no, a.run_id, a.probe_id, a.attack_succeeded, a.category AS detector_flag "
            "FROM mapper_results m JOIN alerts a ON a.id = m.alert_id WHERE m.run_id = ? ORDER BY m.repeat_no", conn,
            params=(run_id,))
    finally:
        conn.close()
    if df.empty:
        return df
    df = df.drop_duplicates("alert_id", keep="last")
    df["family"] = df["probe_id"].map(family)
    df["harmless"] = df["probe_id"].fillna("").str.startswith(HARMLESS)
    df["caught"] = df["detector_flag"].fillna("").str.strip() != ""

    def call(r):
        if not r["valid_json"]:
            return "Failed (API refused)"
        pc = r["predicted_category"]
        return pc if isinstance(pc, str) and pc.strip() else "No attack"   # NULL may arrive as None or NaN
    df["mapper_call"] = df.apply(call, axis=1)

    def group(r):
        if r["harmless"]:
            return "Harmless, " + ("flagged" if r["caught"] else "not flagged")
        if pd.isna(r["attack_succeeded"]):
            return "Attack, not graded"
        return ("Attack worked, " if r["attack_succeeded"] == 1 else "Attack failed, ") + ("caught" if r["caught"] else "missed")
    df["group"] = df.apply(group, axis=1)
    return df


@st.cache_data(show_spinner=False)
def alert(_mtime: float, alert_id: int) -> dict | None:
    conn = connect()
    if conn is None:
        return None
    try:
        r = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if r is None:
            return None
        a = dict(r)
        a["mapper"] = None
        if a.get("predicted_category") is not None or a.get("classified_at"):
            a["mapper"] = {"source": "alert row", "predicted_category": a.get("predicted_category"),
                           "sub_cluster": a.get("sub_cluster"), "lifecycle_phase": a.get("lifecycle_phase"),
                           "confidence": a.get("classification_confidence"), "atlas_technique": a.get("atlas_technique"),
                           "owasp_category": a.get("owasp_category"), "attck_technique": a.get("attck_technique"),
                           "in_scope": a.get("in_scope"), "adversarial": a.get("adversarial"), "rationale": a.get("rationale"),
                           "valid_json": 1}
        elif has_table("mapper_results"):
            m = conn.execute("SELECT * FROM mapper_results WHERE alert_id = ? ORDER BY valid_json DESC, created_at DESC LIMIT 1",
                             (alert_id,)).fetchone()
            if m is not None:
                a["mapper"] = dict(m) | {"source": f"Mapper run {m['run_id']}"}
        return a
    finally:
        conn.close()


@st.cache_data(show_spinner=False)
def explorer_rows(_mtime: float) -> pd.DataFrame:
    """Live attack and harmless rows plus the latest Mapper call where one exists."""
    df = live_rows(_mtime)
    if df.empty:
        return df
    df = df[df["kind"].isin(["garak", "pyrit", "benign"])].copy()
    calls = pd.DataFrame()
    if has_table("mapper_results"):
        conn = connect()
        try:
            calls = pd.read_sql_query(
                "SELECT alert_id AS id, CASE WHEN valid_json = 1 THEN COALESCE(predicted_category, 'No attack') "
                "ELSE 'Failed' END AS mapper_call, confidence AS mapper_confidence FROM mapper_results "
                "ORDER BY valid_json, created_at", conn).drop_duplicates("id", keep="last")
        finally:
            conn.close()
    df = df.merge(calls, on="id", how="left") if not calls.empty else df.assign(mapper_call=None, mapper_confidence=None)
    df["mapper_call"] = df["mapper_call"].fillna("Not classified")
    return df


def prompt_versions() -> list:
    out = []
    if PROMPTS_DIR.exists():
        for f in PROMPTS_DIR.glob("system_prompt_v*.txt"):
            n = re.sub(r"\D", "", f.stem)
            body = [l for l in f.read_text(encoding="utf-8", errors="replace").splitlines() if not l.startswith("# version:")]
            out.append({"version": int(n or 0), "rules": [l.strip() for l in body if re.match(r"^\s*\d+\.\s", l)],
                        "text": "\n".join(body).strip()})
    return sorted(out, key=lambda v: v["version"])


def hardening_history() -> list:
    f = HARDENING_DIR / "history.jsonl"
    rows = []
    if f.exists():
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def decision_test(d: dict) -> dict:
    """What a history.jsonl decision was run on. Entries without 'variants' come from the first decide.py, whose
    attack test always used the replay sets (original + paraphrase), i.e. prompts the hardening had already seen."""
    variants = d.get("variants") or ["original", "paraphrase"]
    if any(v in ("original", "paraphrase", "seen") for v in variants):
        kind = "Replay test (seen prompts)"
    elif "fresh" in variants:
        kind = "Fresh rounds (unseen prompts)"
    else:
        kind = "Live rounds"
    targets = d.get("target_families") or []
    return {"kind": kind, "fresh": kind.startswith("Fresh") or kind == "Live rounds",
            "variants": ", ".join(variants), "targets": ", ".join(targets) if targets else "all families pooled"}


def latest_fresh_decision(decisions: list) -> dict | None:
    """The most recent decision made on fresh/live rounds; replay tests on seen prompts do not count."""
    fresh = [d for d in decisions if decision_test(d)["fresh"]]
    return fresh[-1] if fresh else None


def utility_checks() -> list:
    """Harmless-message refusal checks written by utility_check.py (utility_<old>_<new>_<stamp>.csv)."""
    out = []
    for f in sorted(HARDENING_DIR.glob("utility_*_*_*.csv")):
        try:
            df = pd.read_csv(f)
        except Exception:  # noqa: BLE001
            continue
        cols = [c for c in df.columns if c.startswith("refused_v")]
        if len(cols) == 2:
            ok = df[cols].replace("", pd.NA).dropna()
            out.append({"file": f.name, **{c.replace("refused_", ""): int(ok[c].astype(int).sum()) for c in cols},
                        "messages": len(ok)})
    return out


@st.cache_data(show_spinner=False)
def pilot_scores() -> list:
    files = sorted(EVAL_DIR.glob("pilot_scores_*.json"))
    if not files:
        return []
    try:
        return json.loads(files[-1].read_text(encoding="utf-8"))
    except ValueError:
        return []


@st.cache_data(show_spinner=False)
def ground_truth() -> list:
    f = EVAL_DIR / "ground_truth_final.json"
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else d.get("alerts", [])
    except (OSError, ValueError):
        return []


def heldout_lock() -> dict:
    try:
        return json.loads((EVAL_DIR / "heldout_lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@st.cache_data(show_spinner=False)
def playbooks(_mtime: float) -> pd.DataFrame:
    conn = connect()
    if conn is None:
        return pd.DataFrame()
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
        pred = "predicted_category" if "predicted_category" in cols else "NULL"
        df = pd.read_sql_query(f"SELECT id, source, probe_id, {pred} AS category, playbook, hardening_applied, timestamp "
                               "FROM alerts WHERE playbook IS NOT NULL AND playbook != '' ORDER BY id DESC", conn)
    finally:
        conn.close()

    def parse(s):
        try:
            v = json.loads(s)
            return v if isinstance(v, dict) else {"summary": str(v)}
        except (ValueError, TypeError):
            return {"summary": str(s)}
    if not df.empty:
        df["pb"] = df["playbook"].map(parse)
        df["control"] = df["pb"].map(lambda p: p.get("recommended_control") or "unspecified")
    return df
