import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

st.title("Classification")
ui.intro("How well the Mapper labels alerts against the five-category taxonomy and MITRE ATT&CK, MITRE ATLAS and the OWASP "
         "Top 10 for LLM Applications, first on labelled synthetic alerts, then on real live attacks.")

# ---------------------------------------------------------------- pilot
st.subheader("1. Model selection pilot (synthetic alerts with an answer key)")
scores = data.pilot_scores()
if scores:
    df = pd.DataFrame(scores)
    df = df.sort_values("run_id").groupby(["model", "split"], as_index=False).last()
    df = df.sort_values(["split", "category_accuracy"], ascending=[True, False])
    show = df[["model", "split", "alerts", "repeats", "category_accuracy", "sub_cluster_accuracy_normalized",
               "atlas_any_match", "attack_any_match", "owasp_llm_any_match", "brier"]].rename(columns={
        "model": "Model", "split": "Set", "alerts": "Alerts", "repeats": "Repeats", "category_accuracy": "Category",
        "sub_cluster_accuracy_normalized": "Sub-cluster", "atlas_any_match": "ATLAS", "attack_any_match": "ATT&CK",
        "owasp_llm_any_match": "OWASP", "brier": "Brier (lower is better)"})
    show["Set"] = show["Set"].map({"dev": "Development (16)", "heldout": "Held-out (24)"})
    pc = {c: st.column_config.NumberColumn(format="percent") for c in ["Category", "Sub-cluster", "ATLAS", "ATT&CK", "OWASP"]}
    st.dataframe(show, hide_index=True, width="stretch", column_config=pc)
    st.caption("The prompt was refined on the development set only, then frozen; each held-out run is recorded in "
               "evaluation/heldout_lock.json. Production model: Claude Haiku 5.5 (held-out 91.7%, Brier 0.087 as reported "
               "in mapper/README.md; its held-out score file is not yet in the repository). Framework columns: share of "
               "alerts where at least one expected ID was returned.")
else:
    ui.no_data("No pilot score files found in evaluation/.")

# ---------------------------------------------------------------- live test
st.subheader("2. Live classification test (real attacks and harmless messages)")
mt = data.db_mtime()
runs = data.mapper_runs(mt)
runs = runs[runs["results"] >= 20] if not runs.empty else runs
if runs.empty:
    ui.no_data("No Mapper runs over live alerts in this alert store.")
    st.stop()
run = st.selectbox("Mapper run", list(runs["run_id"]),
                   format_func=lambda r: f"{r} ({int(runs.set_index('run_id').loc[r, 'results'])} alerts)")
m = data.mapper_results(mt, run)
atk, hl = m[~m["harmless"]], m[m["harmless"]]
b_atk, b_hl = int((atk["mapper_call"] == "B").sum()), int((hl["mapper_call"] == "B").sum())
fails = int((m["mapper_call"] == "Failed (API refused)").sum())
ui.kpis([
    ("Attacks confirmed (B)", ui.pct(b_atk, len(atk)), f"{b_atk} of {len(atk)} attacks", "good"),
    ("Harmless called B", f"{b_hl} / {len(hl)}", "false positives at any confidence", "good" if not b_hl else "bad"),
    ("Caught what detection missed", ui.pct(int(((atk['group'] == 'Attack worked, missed') & (atk['mapper_call'] == 'B')).sum()),
                                             int((atk['group'] == 'Attack worked, missed').sum())),
     "successful attacks the detector missed, called B", "accent"),
    ("Failed classifications", f"{fails}", "the API refused the content", "warn" if fails else None),
])

order = ["Attack worked, caught", "Attack worked, missed", "Attack failed, caught", "Attack failed, missed",
         "Harmless, flagged", "Harmless, not flagged"]
ct = pd.crosstab(m["group"], m["mapper_call"]).reindex(order).fillna(0).astype(int)
ct = ct[[c for c in ["B", "C", "A", "D", "No attack", "Failed (API refused)"] if c in ct.columns]]
ct.insert(0, "Alerts", ct.sum(axis=1))
c1, c2 = st.columns([3, 2])
with c1:
    st.markdown("**What the Mapper called each group** (rows: what really happened; columns: Mapper's category)")
    st.dataframe(ct.rename_axis("Group").reset_index(), hide_index=True, width="stretch")
    st.caption("B = prompt injection & jailbreaking. C = conversation & hidden-context compromise: correct for system-prompt "
               "leak attempts, a miss for other attacks.")
with c2:
    st.markdown("**By attack family** (share called B)")
    fam = atk.groupby("family")["mapper_call"].agg(total="size", b=lambda s: int((s == "B").sum())).reset_index()
    fam["rate"] = fam["b"] / fam["total"]
    bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=4, color=ui.ACCENT).encode(
        x=alt.X("rate:Q", title="Called B", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("family:N", title=None, sort="-x"), tooltip=["family", "total", "b", alt.Tooltip("rate:Q", format=".1%")])
    st.altair_chart(ui.chart(bars, 55 * max(len(fam), 2)), width="stretch")

st.markdown(f"**Confidence threshold for auto-hardening: {data.GATE_THRESHOLD}**")
worked = atk[atk["attack_succeeded"] == 1]
rows = []
for t in [x / 100 for x in range(40, 96, 5)]:
    rows.append({"threshold": t, "series": "Successful attacks passed", "n": int(((worked["mapper_call"] == "B") & (worked["confidence"] >= t)).sum())})
    rows.append({"threshold": t, "series": "Harmless messages passed", "n": int(((hl["mapper_call"] == "B") & (hl["confidence"] >= t)).sum())})
sweep = pd.DataFrame(rows)
line = alt.Chart(sweep).mark_line(point=True).encode(
    x=alt.X("threshold:Q", title="Minimum Mapper confidence", scale=alt.Scale(domain=[0.4, 0.95])),
    y=alt.Y("n:Q", title="Alerts passing the gate"),
    color=alt.Color("series:N", title=None, scale=alt.Scale(range=[ui.ACCENT, ui.BAD])),
    tooltip=["threshold", "series", "n"])
rule = alt.Chart(pd.DataFrame({"x": [data.GATE_THRESHOLD]})).mark_rule(strokeDash=[4, 4], color=ui.WARN).encode(x="x:Q")
st.altair_chart(ui.chart(alt.layer(line, rule), 260), width="stretch")
st.caption(f"Only attacks the Mapper calls B at or above this confidence can trigger hardening. At {data.GATE_THRESHOLD}, "
           f"{int(((worked['mapper_call'] == 'B') & (worked['confidence'] >= data.GATE_THRESHOLD)).sum())} of {len(worked)} successful attacks "
           "pass and no harmless message does; it is the lowest threshold at which no harmless message receives any attack label.")

# ---------------------------------------------------------------- matrix
st.subheader("3. Framework coverage")
st.caption("Where this run's labels land in each framework, laid out like the official matrices (Gladwin's view). "
           "Badge = number of alerts; colour = highest severity.")
fw = st.radio("Framework", ["ATLAS", "ATT&CK", "OWASP LLM Top 10"], horizontal=True)
try:
    from mapper import matrix_data, matrix_render
    conn = data.connect()
    try:
        if fw == "OWASP LLM Top 10":
            html_doc, h = matrix_render.render_owasp_strip_html(matrix_data.build_owasp_strip(conn, run_id=run)), 260
        else:
            mx = matrix_data.build_matrix(conn, "atlas" if fw == "ATLAS" else "attack", run_id=run)
            html_doc, h = matrix_render.render_matrix_html(mx, hide_untouched=True), 620
    finally:
        conn.close()
    try:
        st.iframe(html_doc, height=h)
    except Exception:  # noqa: BLE001  older Streamlit
        import streamlit.components.v1 as components
        components.html(html_doc, height=h, scrolling=True)
except ImportError as e:
    st.caption(f"Framework matrix unavailable ({e}).")
