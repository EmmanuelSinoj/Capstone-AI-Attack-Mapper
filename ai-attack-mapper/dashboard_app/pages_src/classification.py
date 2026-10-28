import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

ABOUT = f"""
**What this page shows.** How well the Mapper labels alerts against the five-category taxonomy and MITRE ATT&CK, MITRE ATLAS
and the OWASP Top 10 for LLM Applications: first on labelled synthetic alerts (the Model Selection Pilot), then on real
live attacks.

**Pilot.** The prompt was refined on the development set only (16 alerts), then frozen; each held-out run (24 alerts) is
recorded in evaluation/heldout_lock.json. Production model: Claude Haiku 5.5 (held-out 91.7%, Brier 0.087, mapper/README.md).
Framework columns give the share of alerts where at least one expected ID was returned.

**Categories.** B = prompt injection and jailbreaking. C = conversation and hidden-context compromise: correct for
system-prompt leak attempts, a miss for other attacks.

**Gate threshold {data.GATE_THRESHOLD}.** Only attacks the Mapper calls B at or above this confidence can trigger hardening.
It is the lowest threshold at which no harmless message receives an attack label.

**Framework coverage** places this run's labels on the official matrices (badge = number of alerts; colour = highest severity).
"""

ui.header("Classification", "Mapper results on synthetic and live alerts, mapped to ATT&CK, ATLAS and the OWASP LLM Top 10.",
          ABOUT, "Investigate")

mt = data.db_mtime()
runs = data.mapper_runs(mt)
runs = runs[runs["results"] >= 20] if not runs.empty else runs
m = pd.DataFrame()
if not runs.empty:
    run = st.selectbox("Live Mapper run", list(runs["run_id"]),
                       format_func=lambda r: f"{r} ({int(runs.set_index('run_id').loc[r, 'results'])} alerts)")
    m = data.mapper_results(mt, run)

atk, hl = (m[~m["harmless"]], m[m["harmless"]]) if not m.empty else (m, m)
if not m.empty:
    b_atk, b_hl = int((atk["mapper_call"] == "B").sum()), int((hl["mapper_call"] == "B").sum())
    fails = int((m["mapper_call"] == "Failed (API refused)").sum())
    missed_det = atk[atk["group"] == "Attack worked, missed"]
    worked = atk[atk["attack_succeeded"] == 1]
    gate_pass = int(((worked["mapper_call"] == "B") & (worked["confidence"] >= data.GATE_THRESHOLD)).sum())
    ui.kpis([
        ("Attacks confirmed (B)", ui.pct(b_atk, len(atk)), f"{b_atk} of {len(atk)} live attacks", "good"),
        ("Harmless called B", f"{b_hl} / {len(hl)}", "false positives at any confidence", "good" if not b_hl else "bad"),
        ("Caught what detection missed", ui.pct(int((missed_det["mapper_call"] == "B").sum()), len(missed_det)),
         "missed successful attacks called B", "accent"),
        (f"Pass the gate (≥ {data.GATE_THRESHOLD})", f"{gate_pass} / {len(worked)}", "successful attacks", "accent"),
        ("Held-out accuracy", "91.7%", "22 of 24 synthetic alerts (pilot)", "good"),
        ("Failed classifications", f"{fails}", "the API refused the content", "warn" if fails else None),
    ])
else:
    ui.kpis([("Held-out accuracy", "91.7%", "22 of 24 synthetic alerts (pilot)", "good"),
             ("Live Mapper run", "None", "no live classification run in this alert store", "warn")])

with ui.panel("Model selection pilot", "synthetic alerts with an answer key"):
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
        pc = {c: st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1)
              for c in ["Category", "Sub-cluster", "ATLAS", "ATT&CK", "OWASP"]}
        st.dataframe(show, hide_index=True, width="stretch", column_config=pc)
    else:
        ui.no_data("No pilot score files found in evaluation/.")

if m.empty:
    ui.no_data("No Mapper runs over live alerts in this alert store.")
    st.stop()

order = ["Attack worked, caught", "Attack worked, missed", "Attack failed, caught", "Attack failed, missed",
         "Harmless, flagged", "Harmless, not flagged"]
cols = ["B", "C", "A", "D", "E", "No attack", "Failed (API refused)"]
c1, c2 = st.columns([3, 2])
with c1:
    with ui.panel("Mapper category by what really happened", "alerts"):
        ct = m.groupby(["group", "mapper_call"]).size().reset_index(name="n")
        heat = alt.Chart(ct).mark_rect(stroke=ui.PANEL, strokeWidth=2).encode(
            x=alt.X("mapper_call:N", title="Mapper category", sort=cols, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("group:N", title=None, sort=order, axis=alt.Axis(labelLimit=200)),
            color=alt.Color("n:Q", title="Alerts", scale=alt.Scale(scheme="blues")),
            tooltip=["group", "mapper_call", "n"])
        txt = alt.Chart(ct).mark_text(fontSize=12, fontWeight="bold", color="#0B1220").encode(
            x=alt.X("mapper_call:N", sort=cols), y=alt.Y("group:N", sort=order), text="n:Q")
        st.altair_chart(ui.chart(alt.layer(heat, txt), alt.Step(32)), width="stretch")
with c2:
    with ui.panel("Called B, by attack family"):
        fam = atk.groupby("family")["mapper_call"].agg(total="size", b=lambda s: int((s == "B").sum())).reset_index()
        fam["rate"] = fam["b"] / fam["total"]
        bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=3).encode(
            x=alt.X("rate:Q", title="Called B", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
            y=alt.Y("family:N", title=None, sort="-x"),
            color=alt.Color("family:N", legend=None, scale=alt.Scale(domain=list(ui.FAMILY_COLOR), range=list(ui.FAMILY_COLOR.values()))),
            tooltip=["family", "total", "b", alt.Tooltip("rate:Q", format=".1%")])
        st.altair_chart(ui.chart(bars, 260), width="stretch")

c1, c2 = st.columns(2)
with c1:
    with ui.panel("Confidence distribution", "valid classifications"):
        v = m[m["valid_json"] == 1].copy()
        v["kind"] = v["harmless"].map({True: "Harmless", False: "Attack"})
        hist = alt.Chart(v).mark_bar(opacity=0.85).encode(
            x=alt.X("confidence:Q", bin=alt.Bin(step=0.05), title="Mapper confidence"),
            y=alt.Y("count():Q", title="Alerts", stack=None),
            color=alt.Color("kind:N", title=None, scale=alt.Scale(domain=["Attack", "Harmless"], range=[ui.ACCENT, ui.PURPLE])),
            tooltip=["kind", alt.Tooltip("count():Q", title="Alerts")])
        rule = alt.Chart(pd.DataFrame({"x": [data.GATE_THRESHOLD]})).mark_rule(strokeDash=[4, 4], color=ui.WARN).encode(x="x:Q")
        st.altair_chart(ui.chart(alt.layer(hist, rule), 230), width="stretch")
with c2:
    with ui.panel("Gate threshold sweep", f"dashed line = {data.GATE_THRESHOLD}"):
        rows = []
        for t in [x / 100 for x in range(40, 96, 5)]:
            rows.append({"threshold": t, "series": "Successful attacks passed",
                         "n": int(((worked["mapper_call"] == "B") & (worked["confidence"] >= t)).sum())})
            rows.append({"threshold": t, "series": "Harmless messages passed",
                         "n": int(((hl["mapper_call"] == "B") & (hl["confidence"] >= t)).sum())})
        sweep = pd.DataFrame(rows)
        line = alt.Chart(sweep).mark_line(point=True).encode(
            x=alt.X("threshold:Q", title="Minimum Mapper confidence", scale=alt.Scale(domain=[0.4, 0.95])),
            y=alt.Y("n:Q", title="Alerts passing the gate"),
            color=alt.Color("series:N", title=None, scale=alt.Scale(range=[ui.ACCENT, ui.BAD])),
            tooltip=["threshold", "series", "n"])
        rule = alt.Chart(pd.DataFrame({"x": [data.GATE_THRESHOLD]})).mark_rule(strokeDash=[4, 4], color=ui.WARN).encode(x="x:Q")
        st.altair_chart(ui.chart(alt.layer(line, rule), 230), width="stretch")

c1, c2 = st.columns(2)
for col, label, key in ((c1, "Top ATLAS techniques", "atlas_technique"), (c2, "Top OWASP LLM categories", "owasp_category")):
    with col:
        with ui.panel(label, "valid classifications"):
            ids = pd.Series([i for v in m.loc[m["valid_json"] == 1, key] for i in data.ids(v)])
            if ids.empty:
                st.caption("No IDs returned.")
            else:
                st.dataframe(ids.value_counts().head(8).rename_axis("ID").reset_index(name="Alerts"), hide_index=True, width="stretch")

with ui.panel("Framework coverage", "where this run's labels land"):
    fw = st.radio("Framework", ["ATLAS", "ATT&CK", "OWASP LLM Top 10"], horizontal=True, label_visibility="collapsed")
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
