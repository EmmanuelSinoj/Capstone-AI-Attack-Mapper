"""AI Attack Mapper dashboard: one app, one page per part of the pipeline.

  cd ai-attack-mapper
  streamlit run dashboard_app/app.py

Reads the shared alert store read-only. Database: ALERTS_DB_PATH (default alert_store/alerts.db).
In PowerShell:  $env:ALERTS_DB_PATH = "alert_store\\alerts.db"
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
    st.markdown("**AI Attack Mapper**")
    if data.DB_PATH.exists():
        st.caption(f"Alert store: `{data.DB_PATH.name}`")
    else:
        st.error(f"Alert store not found: {data.DB_PATH}. Set ALERTS_DB_PATH.")
    if st.button("Refresh data", icon=":material/refresh:", width="stretch"):
        st.cache_data.clear()
        st.rerun()

nav.run()
