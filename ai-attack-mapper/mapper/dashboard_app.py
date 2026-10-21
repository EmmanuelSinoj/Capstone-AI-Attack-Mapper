"""
mapper/dashboard_app.py

The Mapper's own dashboard (Classification & Defense track), over the shared
Alert Store. NOT the same as dashboard/app.py at the repo root (Aneeq's Live
Ops Console).

Sections:
  1. Production classification -- alerts the pipeline classified
     (db.save_classification -> predicted_category / classified_at), with a
     sidebar button that classifies everything in db.get_mapper_queue().
  2. Model Selection Pilot -- every dev / held-out run in mapper_results,
     scored by pilot.score_runs() (mapper_scores view + framework IDs +
     confidence calibration). Runs are started from the CLI
     (python -m mapper.pilot run ...), not from here, so a held-out run can
     never be triggered by a stray click.
  3. Visual ATT&CK / ATLAS / OWASP matrix -- for production alerts or for any
     one pilot run.
  4. Alert detail.

Severity is not stored in the shared store; it's deterministic, so it is
recomputed on read (severity.severity_from_fields).

Run it (from ai-attack-mapper/):
    pip install -r mapper/requirements.txt
    streamlit run mapper/dashboard_app.py
"""

import os
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# `streamlit run` executes this file as a bare script and only puts mapper/ on
# sys.path; put the repo root there so `mapper` and `alert_store` import as packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mapper import client  # noqa: E402
from mapper import framework_reference as fw_ref  # noqa: E402
from mapper import matrix_data, matrix_render, pilot  # noqa: E402
from mapper.pipeline import classify_pending_alerts  # noqa: E402
from mapper.severity import LEVELS as SEVERITY_LEVELS, severity_from_fields  # noqa: E402
from alert_store import db as alert_db  # noqa: E402

st.set_page_config(page_title="AI Attack Mapper -- Classification Dashboard", layout="wide")

FW_COLS = {"attack": "attck_technique", "atlas": "atlas_technique", "owasp_llm": "owasp_category"}


# ---------------------------------------------------------------- data ----

def _get_conn() -> sqlite3.Connection:
    """Fresh connection per script run -- NOT cached: sqlite3 connections are
    thread-affine and Streamlit may rerun on another thread."""
    # MAPPER_DB lets the dashboard open a different database (e.g. alert_store/pilot.db)
    # without touching the shared alerts.db: `$env:MAPPER_DB="alert_store\pilot.db"` in PowerShell.
    return alert_db.get_connection(os.environ.get("MAPPER_DB") or None)


def _load_alerts_df(conn: sqlite3.Connection) -> pd.DataFrame:
    rows = conn.execute(
        "SELECT id, source, input, output, detector, category AS detector_flag, predicted_category, "
        "classified_at, in_scope, adversarial, sub_cluster, lifecycle_phase, attck_technique, "
        "atlas_technique, owasp_category, classification_confidence, rationale, "
        "ground_truth_category, hardening_applied, timestamp FROM alerts ORDER BY id"
    ).fetchall()
    df = pd.DataFrame([dict(r) for r in rows])
    if df.empty:
        return df
    sev = [severity_from_fields(r.predicted_category, r.sub_cluster, r.adversarial,
                                r.classification_confidence, r.in_scope) if r.classified_at else
           {"severity": None, "severity_score": None} for r in df.itertuples()]
    df["severity"] = [s["severity"] for s in sev]
    df["severity_score"] = [s["severity_score"] for s in sev]
    return df


# ------------------------------------------------------------- sidebar ----

st.sidebar.header("Classify pending alerts")
backend = st.sidebar.selectbox("Backend", ["claude", "ollama"], index=0)  # Haiku 5.5 is production
default_model = client.default_ollama_model() if backend == "ollama" else client.default_claude_model()
model = st.sidebar.text_input("Model", value=default_model)
host = st.sidebar.text_input("Ollama host (blank = OLLAMA_HOST / localhost)", value="") \
    if backend == "ollama" else None
api_key = st.sidebar.text_input("Anthropic API key (blank = ANTHROPIC_API_KEY)", value="", type="password") \
    if backend == "claude" else None
limit = st.sidebar.number_input("Max alerts this run (0 = all pending)", min_value=0, value=0, step=1)
st.sidebar.caption("Production path: stores the answer on the alert row. Pilot runs "
                   "(dev / held-out) are started from the CLI: `python -m mapper.pilot run ...`")

if st.sidebar.button("Classify pending alerts", type="primary"):
    kwargs = {"model": model} if model else {}
    if host:
        kwargs["host"] = host
    if api_key:
        kwargs["api_key"] = api_key
    with st.spinner(f"Classifying pending alerts against {backend}..."):
        outcomes = classify_pending_alerts(conn=_get_conn(), backend=backend, limit=(limit or None), **kwargs)
    # session_state survives st.rerun(); a local variable would be wiped before it renders.
    st.session_state["last_classify_outcomes"] = outcomes
    st.session_state["last_classify_backend"] = backend
    st.rerun()

st.sidebar.divider()
if "last_classify_outcomes" in st.session_state:
    outcomes = st.session_state["last_classify_outcomes"]
    ran_backend = st.session_state.get("last_classify_backend", "?")
    if not outcomes:
        st.sidebar.info("Last run: nothing was waiting for the Mapper.")
    else:
        ok = sum(1 for o in outcomes if o["status"] == "ok")
        (st.sidebar.success if ok == len(outcomes) else st.sidebar.error)(
            f"Last run ({ran_backend}): classified {ok}/{len(outcomes)} alert(s).")
        failed = [o for o in outcomes if o["status"] != "ok"]
        if failed:
            with st.sidebar.expander(f"{len(failed)} failed -- details", expanded=True):
                for o in failed:
                    st.write(f"alert {o['alert_id']}: {o.get('error', 'unknown error')}")
        warned = [o for o in outcomes if o.get("warning")]
        if warned:
            st.sidebar.warning(warned[0]["warning"])
    if st.sidebar.button("Dismiss"):
        del st.session_state["last_classify_outcomes"]
        st.rerun()
if st.sidebar.button("Refresh data"):
    st.rerun()


# -------------------------------------------------------------- header ----

st.title("AI Attack Mapper -- Classification Dashboard")
versions = fw_ref._load().get("versions", {})
st.caption(
    "Category, severity, confidence and framework mapping for every alert the Mapper has touched, "
    f"resolved against ATT&CK v{versions.get('attack', '?')}, ATLAS {versions.get('atlas', '?')} "
    "and the OWASP LLM Top 10 (2026)."
)

conn = _get_conn()
df = _load_alerts_df(conn)
if df.empty:
    st.warning("alerts.db has no rows yet. Load the synthetic alerts "
               "(`python3 synthetic_alerts/load_alerts.py --db alert_store/alerts.db --schema alert_store/schema.sql`) "
               "or start the live testbed, then refresh.")
    st.stop()

classified = df[df["classified_at"].notna()]
in_scope = classified[classified["in_scope"] != 0]
queue = alert_db.get_mapper_queue(conn)


# ------------------------------------------------- 1. production KPIs ----

st.header("1. Production classification")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total alerts", len(df))
c2.metric("Classified", len(classified))
c3.metric("Waiting for the Mapper", len(queue),
          help="Unclassified synthetic alerts + unclassified live alerts the detector flagged.")
c4.metric("Mean confidence", f"{in_scope['classification_confidence'].mean():.2f}"
          if in_scope["classification_confidence"].notna().any() else "--")
gt = in_scope[in_scope["ground_truth_category"].notna()]
c5.metric("Category accuracy (vs. answer key)", f"{(gt['predicted_category'] == gt['ground_truth_category']).mean():.0%}"
          if not gt.empty else "--", help="All classified alerts with a key, regardless of split. "
          "Pilot numbers by split are in section 2.")

d1, d2, d3 = st.columns(3)
with d1:
    st.subheader("Category")
    if not classified.empty:
        st.bar_chart(classified["predicted_category"].fillna("(out of scope)").value_counts())
    else:
        st.caption("Nothing classified yet.")
with d2:
    st.subheader("Severity")
    if in_scope["severity"].notna().any():
        st.bar_chart(in_scope["severity"].value_counts().reindex(SEVERITY_LEVELS).fillna(0))
    else:
        st.caption("No severity yet.")
with d3:
    st.subheader("Confidence")
    conf = in_scope["classification_confidence"].dropna()
    if not conf.empty:
        labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
        # explicit string labels: Altair can't serialize pandas Interval objects
        bins = pd.cut(conf, bins=[0, 0.2, 0.4, 0.6, 0.8, 1.0], include_lowest=True, labels=labels)
        st.bar_chart(bins.value_counts().reindex(labels).fillna(0))
    else:
        st.caption("No confidence scores yet.")

st.subheader("Framework IDs: real vs. malformed")
st.caption("Each ID the model returned, checked against the real ATT&CK / ATLAS / OWASP data. "
           "'Malformed' = not exactly a real ID (a made-up suffix like .00x, a name appended, "
           "or the wrong framework).")
fw_stats = []
for fw_key, col in FW_COLS.items():
    table = fw_ref._load()[fw_key]
    ids = [i for v in classified[col] for i in fw_ref.parse_id_list(v)]
    fw_stats.append({"framework": fw_key, "real": sum(1 for i in ids if i in table),
                     "malformed": sum(1 for i in ids if i not in table)})
fw_df = pd.DataFrame(fw_stats).set_index("framework")
k1, k2 = st.columns([1, 2])
k1.dataframe(fw_df, width="stretch")
k2.bar_chart(fw_df)


# --------------------------------------------- 2. model selection pilot ----

st.header("2. Model Selection Pilot (dev / held-out)")
scores = pilot.score_runs(conn)
lock = pilot._load_lock()
if lock.get("frozen"):
    f = lock["frozen"]
    st.info(f"Frozen for held-out: {f['backend']} / {f['model']}, prompt {f['prompt_version']} "
            f"({f['prompt_fingerprint']}). Held-out runs so far: {len(lock.get('heldout_runs', []))}.")
else:
    st.caption("Held-out is locked until a model and prompt are frozen (`python -m mapper.pilot freeze ...`). "
               "Tune on dev only.")
if not scores:
    st.caption("No pilot runs yet. Load the answer key, assign the split, then "
               "`python -m mapper.pilot run --backend ollama --model <model>`.")
else:
    cols = ["run_id", "split", "model", "prompt_version", "alerts", "repeats", "valid_json_rate",
            "category_accuracy", "category_accuracy_strict", "sub_cluster_accuracy_normalized",
            "adversarial_accuracy", "atlas_primary_match", "atlas_any_match", "attack_any_match",
            "owasp_llm_any_match", "malformed_id_rate", "mean_confidence", "overconfidence_gap",
            "ece_5bin", "repeat_consistency"]
    st.dataframe(pd.DataFrame(scores)[cols], width="stretch", hide_index=True)
    st.caption("Dev has 4 alerts per category: one alert moves dev accuracy by 6.25 points, so don't "
               "over-read small differences. Report dev and held-out side by side; a large gap means "
               "the prompt was overfitted to dev.")

    run_ids = [s["run_id"] for s in scores]
    chosen = st.selectbox("Inspect a run", run_ids, index=len(run_ids) - 1)
    s = next(x for x in scores if x["run_id"] == chosen)
    p1, p2 = st.columns(2)
    with p1:
        st.markdown("**Confusion matrix** (rows = answer key, columns = Mapper)")
        conf_rows = {}
        for k, n in s["confusion"].items():
            t, p = k.split("->")
            conf_rows.setdefault(t, {})[p] = n
        cm = pd.DataFrame(conf_rows).T.fillna(0).astype(int)
        cm = cm.reindex(sorted(cm.index), fill_value=0)
        cm = cm[[c for c in ["A", "B", "C", "D", "E", "None", "invalid"] if c in cm.columns]]
        st.dataframe(cm, width="stretch")
    with p2:
        st.markdown("**Confidence calibration** (per confidence band: how often the category was right)")
        res = pd.DataFrame([dict(r) for r in conn.execute(
            "SELECT confidence, category_correct FROM mapper_scores WHERE run_id = ? AND valid_json = 1 "
            "AND confidence IS NOT NULL AND category_correct IS NOT NULL", (chosen,))])
        if not res.empty:
            labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
            res["band"] = pd.cut(res["confidence"], bins=[0, 0.2, 0.4, 0.6, 0.8, 1.0], include_lowest=True,
                                 labels=labels)
            cal = res.groupby("band", observed=False).agg(replies=("category_correct", "size"),
                                                          accuracy=("category_correct", "mean"),
                                                          mean_confidence=("confidence", "mean"))
            st.dataframe(cal.round(2), width="stretch")
            st.caption(f"Overconfidence gap {s['overconfidence_gap']}, Brier {s['brier']}, ECE {s['ece_5bin']} "
                       "(lower is better; gap > 0 means more confident than accurate).")
    if s["split"] == "dev":
        st.caption(f"Error review: `python -m mapper.pilot errors --run-id {chosen}`")


# --------------------------------------------------------- 3. visual matrix ----

st.header("3. Visual matrix -- ATT&CK / ATLAS / OWASP LLM Top 10")
st.caption("Laid out like attack.mitre.org / atlas.mitre.org: tactics as columns, techniques as cells, "
           "colored by the highest severity among the alerts mapped to them (badge = number of alerts). "
           "A colored left edge means only a sub-technique was hit; a colored column header means the "
           "tactic ID itself was returned. Click a name to open it on the real site.")
m1, m2, m3 = st.columns([2, 3, 1])
matrix_tab = m1.radio("Framework", ["ATT&CK", "ATLAS", "OWASP LLM Top 10"], horizontal=True, key="matrix_tab")
source_options = ["Production (alert rows)"] + [s["run_id"] for s in scores if s["split"] == "dev"]
matrix_source = m2.selectbox("Mapping from", source_options, key="matrix_source",
                             help="Held-out runs are left out on purpose.")
hide_untouched = m3.checkbox("Hide untouched", value=True)
run_id = None if matrix_source.startswith("Production") else matrix_source

if matrix_tab in ("ATT&CK", "ATLAS"):
    fw_key = "attack" if matrix_tab == "ATT&CK" else "atlas"
    matrix = matrix_data.build_matrix(conn, fw_key, run_id=run_id)
    hit_cols = sum(1 for t in matrix["tactics"] if t["id"] in matrix["tactic_hits"] or any(
        r["severity"] or r["child_severity"] for r in matrix["columns"].get(t["id"], [])))
    st.caption(f"{hit_cols} of {len(matrix['tactics'])} tactic columns have at least one alert mapped to them.")
    st.iframe(matrix_render.render_matrix_html(matrix, hide_untouched=hide_untouched), height=620, width="stretch")
else:
    st.iframe(matrix_render.render_owasp_strip_html(matrix_data.build_owasp_strip(conn, run_id=run_id)),
              height=260, width="stretch")


# ------------------------------------------------------------ 4. alerts ----

st.header("4. Alerts")
display_df = df[["id", "source", "detector_flag", "predicted_category", "severity", "classification_confidence",
                 "ground_truth_category", "sub_cluster", "timestamp"]].rename(columns={
    "classification_confidence": "confidence", "ground_truth_category": "answer_key",
    "predicted_category": "mapper_category"})
st.dataframe(display_df, width="stretch", hide_index=True)

selected_id = st.selectbox("Alert detail", df["id"].tolist())
row = df[df["id"] == selected_id].iloc[0]
a1, a2 = st.columns(2)
with a1:
    st.markdown(f"**Source:** {row['source']}  |  **Detector:** {row['detector'] or '--'}  |  "
                f"**Detector flag:** {row['detector_flag'] or '--'}")
    st.markdown("**Input**")
    st.code(row["input"] or "", language=None, wrap_lines=True)
    st.markdown("**Output**")
    st.code(row["output"] or "(none)", language=None, wrap_lines=True)
with a2:
    if row["classified_at"]:
        adv = {1: "yes", 0: "no"}.get(row["adversarial"], "--")
        st.markdown(f"**Mapper category:** {row['predicted_category'] or '(out of scope)'}  |  "
                    f"**Answer key:** {row['ground_truth_category'] or '--'}")
        st.markdown(f"**Sub-cluster:** {row['sub_cluster'] or '--'}  |  **Adversarial:** {adv}")
        st.markdown(f"**Confidence:** {row['classification_confidence']}  |  "
                    f"**Severity:** {row['severity']} (score {row['severity_score']})")
        st.markdown("**Rationale**")
        st.text(row["rationale"] or "--")  # plain text: model output is never rendered as markdown
        for fw_key, col in FW_COLS.items():
            st.markdown(f"**{fw_key.upper()}**")
            ids = fw_ref.parse_id_list(row[col])
            if not ids:
                st.caption("(none)")
            for raw_id in ids:
                r = fw_ref.lookup(fw_key, raw_id)
                exact = raw_id.strip() in fw_ref._load()[fw_key]
                if r.resolved and exact:
                    st.markdown(f"- `{r.id}` -- {r.name} -- [{r.url}]({r.url})")
                elif r.resolved:
                    st.markdown(f"- :orange[`{raw_id}`] -- malformed; closest real ID `{r.id}` {r.name}")
                else:
                    st.markdown(f"- :red[`{raw_id}`] -- not a real {fw_key} ID")
    else:
        st.caption("Not classified yet.")
