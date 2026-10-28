import pandas as pd
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** The evidence behind the claims: what the system was tested on, how the test data was kept separate
from tuning, and the results so far.

- **Synthetic test set:** 40 alerts written from MITRE ATLAS case studies and the literature review, each with an answer key
  (category, sub-cluster, framework IDs). Split once into 16 development and 24 held-out alerts (seed 42).
- **Held-out protection:** the prompt is frozen before any held-out run, and every held-out run is logged; the held-out set
  is never used to tune the prompt.
- **Still to come:** precision, recall and the confusion matrix from the accuracy harness, and the before/after attack
  success from the defensive-effectiveness harness, once they have run.
"""
ui.header("Evaluation", "Test data, held-out protection and the headline results.", ABOUT, "Prove")

gt = data.ground_truth()
lock = data.heldout_lock()
c1, c2 = st.columns(2)
with c1, ui.panel("Synthetic test set"):
    if gt:
        df = pd.DataFrame(gt)
        counts = df.groupby("category").size().rename("Alerts").reset_index().rename(columns={"category": "Category"})
        st.dataframe(counts, hide_index=True, width="stretch")
        st.caption(f"{len(df)} alerts with an answer key; 16 development, 24 held-out.")
    else:
        ui.no_data("evaluation/ground_truth_final.json not found.")
with c2, ui.panel("Held-out protection"):
    if lock.get("frozen"):
        f = lock["frozen"]
        st.markdown(f"Prompt **{f.get('prompt_version')}** (fingerprint `{f.get('prompt_fingerprint')}`) frozen before any held-out run.")
        st.dataframe(pd.DataFrame(lock.get("heldout_runs", [])).rename(columns={"run_id": "Held-out run", "at": "At",
                                                                                "rerun_reason": "Note"}),
                     hide_index=True, width="stretch")
    else:
        ui.no_data("No held-out lock found.")

mt = data.db_mtime()
live = data.live_rows(mt)
det = data.detection_summary(live[live["kind"].isin(["garak", "pyrit", "benign"]) & ~live["invalid_round"]]) if not live.empty else None
runs = data.mapper_runs(mt)
runs = runs[runs["results"] >= 20] if not runs.empty else runs
m = data.mapper_results(mt, runs.iloc[0]["run_id"]) if not runs.empty else pd.DataFrame()
atk, hl = (m[~m["harmless"]], m[m["harmless"]]) if not m.empty else (m, m)
ui.kpis([("Classification, held-out", "91.7%", "22 of 24 unseen synthetic alerts (Haiku 5.5, mapper/README.md)", "good"),
         ("Classification, live", ui.pct(int((atk["mapper_call"] == "B").sum()), len(atk)) if len(atk) else "–",
          f"{int((atk['mapper_call'] == 'B').sum())} of {len(atk)} live attacks called B; {int((hl['mapper_call'] == 'B').sum())} of {len(hl)} harmless" if len(atk) else "no live Mapper run", "good"),
         ("Detection, successful attacks", ui.pct(det["worked_caught"], det["worked"]) if det else "–",
          f"{det['worked_caught']:,} of {det['worked']:,} caught in valid rounds" if det else "", "good"),
         ("Defensive effectiveness", "Pending", "fresh rounds on original vs hardened prompt", "warn")])

