"""AI Attack Mapper dashboard: one app, one page per part of the pipeline, in a dark SIEM-style layout.

  cd ai-attack-mapper
  streamlit run dashboard_app/app.py

Reads the shared alert store read-only. Database: ALERTS_DB_PATH (default alert_store/alerts.db).
In PowerShell:  $env:ALERTS_DB_PATH = "alert_store\\alerts.db"
The theme comes from ai-attack-mapper/.streamlit/config.toml (start Streamlit from the ai-attack-mapper folder).
"""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data  # noqa: E402
import ui  # noqa: E402

st.set_page_config(page_title="AI Attack Mapper", page_icon=":material/shield:", layout="wide")
ui.setup()

PAGES = Path(__file__).resolve().parent / "pages_src"
nav = st.navigation({
    "Situation": [st.Page(PAGES / "overview.py", title="Overview", icon=":material/dashboard:", default=True)],
    "Investigate": [
        st.Page(PAGES / "campaigns.py", title="Attack campaigns", icon=":material/bolt:"),
        st.Page(PAGES / "detection.py", title="Detection", icon=":material/radar:"),
        st.Page(PAGES / "classification.py", title="Classification", icon=":material/category:"),
        st.Page(PAGES / "explorer.py", title="Alert explorer", icon=":material/search:"),
    ],
    "Respond": [
        st.Page(PAGES / "hardening.py", title="Auto-hardening", icon=":material/shield_lock:"),
        st.Page(PAGES / "playbooks.py", title="Playbooks", icon=":material/menu_book:"),
    ],
    "Prove": [st.Page(PAGES / "evaluation.py", title="Evaluation", icon=":material/fact_check:")],
})

with st.sidebar:
    st.markdown("**AI Attack Mapper**  \n<span class='muted'>Security console</span>", unsafe_allow_html=True)
    if data.DB_PATH.exists():
        st.caption(f"Alert store: `{data.DB_PATH.name}`")
        bounds = data.time_bounds(data.db_mtime())
        if bounds:
            tr = st.date_input("Time range", value=bounds, min_value=bounds[0], max_value=bounds[1], format="DD/MM/YYYY",
                               help="Filters attack and harmless events on Overview, Attack campaigns, Detection and the Alert explorer.")
            st.session_state["time_range"] = tr if isinstance(tr, (tuple, list)) and len(tr) == 2 else bounds
        live = data.live_rows(data.db_mtime())
        versions = sorted(int(v) for v in live["version"].dropna().unique()) if not live.empty else []
        if versions:
            st.session_state["prompt_versions"] = st.multiselect(
                "Prompt versions", versions, format_func=lambda v: f"v{v}", placeholder="All versions", key="pv_filter",
                help="Filters attack and harmless events by the system-prompt version they were sent to.")
        runs = data.mapper_runs(data.db_mtime())
        if not runs.empty:
            labels = {r.run_id: f"{r.run_id} · {int(r.results):,} alerts" for r in runs.itertuples()}
            ids = list(runs["run_id"])
            default = next((i for i, r in enumerate(runs.itertuples()) if r.live > 0), 0)
            st.session_state["mapper_run"] = st.selectbox(
                "Mapper run", ids, index=default, format_func=lambda r: labels[r], key="mapper_run_pick",
                help="The classification run shown on Overview, Classification, Alert explorer and Evaluation.")
        else:
            st.session_state["mapper_run"] = None
    else:
        st.error(f"Alert store not found: {data.DB_PATH}. Set ALERTS_DB_PATH.")
    if st.button("Refresh data", icon=":material/refresh:", width="stretch"):
        st.cache_data.clear()
        st.rerun()

nav.run()
