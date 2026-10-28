import altair as alt
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** The recommended response for each classified alert: what happened, the containment steps, and the
defensive control family it maps to (from the project's Category E controls crosswalk). Alerts whose attack was already
patched by auto-hardening note the action already taken.
"""
ui.header("Playbooks", "Recommended response and defensive control for each classified alert.", ABOUT, "Respond")

mt = data.db_mtime()
pb = data.playbooks(mt)
if pb.empty:
    ui.no_data("No playbooks in the alert store yet. They appear here once playbook generation has run on classified alerts.")
    st.stop()

ui.kpis([("Playbooks", f"{len(pb):,}", "alerts with a recommended response", None),
         ("Control families used", f"{pb['control'].nunique()}", "distinct recommended controls", None),
         ("Already hardened", f"{int(pb['hardening_applied'].fillna(0).sum())}", "alerts whose attack was already patched", None)])

cc = pb["control"].value_counts().rename_axis("control").reset_index(name="n")
with ui.panel("Playbooks by recommended control"):
    bars = alt.Chart(cc).mark_bar(cornerRadiusEnd=3, color=ui.ACCENT).encode(
        x=alt.X("n:Q", title="Playbooks"), y=alt.Y("control:N", title=None, sort="-x"), tooltip=["control", "n"])
    st.altair_chart(ui.chart(bars, 40 * max(len(cc), 2)), width="stretch")

control = st.selectbox("Recommended control", ["All"] + list(cc["control"]))
view = pb if control == "All" else pb[pb["control"] == control]
for _, r in view.head(50).iterrows():
    p = r["pb"]
    with st.expander(f"Alert {r['id']} · {r['probe_id'] or r['source']} · category {r['category'] or '–'}"):
        if p.get("summary"):
            st.markdown(p["summary"])
        for i, s in enumerate(p.get("containment_steps") or [], 1):
            st.markdown(f"{i}. {s}")
        if p.get("follow_up"):
            st.markdown("**Follow-up:** " + "; ".join(map(str, p["follow_up"])))
        st.caption(f"Control: {r['control']} · already hardened: {p.get('already_hardened', '–')}")
