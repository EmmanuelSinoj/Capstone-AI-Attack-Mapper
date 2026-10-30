import html

import altair as alt
import pandas as pd
import streamlit as st

import alert_view
import data
import ui

ABOUT = f"""
**What this page shows.** How well the Mapper labels alerts against the five-category taxonomy and MITRE ATT&CK, MITRE ATLAS
and the OWASP Top 10 for LLM Applications: first on labelled synthetic alerts (the Model Selection Pilot), then on real
live attacks.

**Mapper run.** Everything on this page comes from the Mapper run chosen in the sidebar. The line under the title lists
the attack rounds (and synthetic alerts) the run covered. Live alerts and synthetic alerts are shown separately: live
alerts are judged against what really happened, synthetic alerts against their answer key.

**Pilot.** The prompt was refined on the development set only (16 alerts), then frozen; each held-out run (24 alerts) is
recorded in evaluation/heldout_lock.json. Production model: Claude Haiku 5.5 (held-out 91.7%, Brier 0.087, mapper/README.md).
Framework columns give the share of alerts where at least one expected ID was returned.

**Categories.** B = prompt injection and jailbreaking. C = conversation and hidden-context compromise: correct for
system-prompt leak attempts, a miss for other attacks.

**Gate threshold {data.GATE_THRESHOLD}.** Only attacks the Mapper calls B at or above this confidence can trigger hardening.
It is the lowest threshold at which no harmless message receives an attack label.

**Browse by technique** lists every ATLAS, ATT&CK or OWASP LLM identifier the Mapper assigned in this run. Select a
technique to list its alerts, then select an alert to open its request, reply, verdicts and rationale.

**Reading the results.** Attacks confirmed (B) should be high; harmless messages called B should be 0; successful attacks
passing the gate are the ones auto-hardening is built from. Encoded attacks are the Mapper's known weak spot.

**Framework coverage** lists, per tactic, the techniques this run assigned, with the number of alerts and the highest
severity (colour). OWASP LLM Top 10 shows all ten risks; unused ones are dimmed. The full matrices are under Details.

**Details** holds the method views: the Model Selection Pilot table (the held-out accuracy itself is on Evaluation), the
confidence distribution, the gate threshold sweep, failed classifications, the share of detector misses the Mapper still
confirmed, and the full framework matrices.
"""

ui.header("Classification", "Synthetic and live alert classifications across ATT&CK, ATLAS and OWASP LLM Top 10.",
          ABOUT, "Investigate")

mt = data.db_mtime()
run = data.selected_run()
m = data.mapper_results(mt, run) if run else pd.DataFrame()

if m.empty:
    ui.scope("no Mapper run in this alert store" if not run else f"Mapper run {run} has no results")
    ui.no_data("No Mapper runs in this alert store.")
    with ui.details():
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
    st.stop()

info = data.mapper_runs(mt).set_index("run_id").loc[run]
lv, syn = m[m["source"] == "live"], m[m["source"] == "synthetic"]
atk, hl = lv[~lv["harmless"]], lv[lv["harmless"]]
ui.scope(f"Mapper run {run}", f"{info['model']}, prompt {info['prompt_version']}",
         f"{len(m):,} alerts ({len(lv):,} live, {len(syn):,} synthetic)")
rc = lv["run_id"].value_counts()
tags = [f"{r} · {n:,}" for r, n in rc.items()] + ([f"synthetic alerts · {len(syn):,}"] if len(syn) else [])
st.markdown('<div class="scope"><span class="k">Rounds</span> ' + "".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags)
            + "</div>", unsafe_allow_html=True)

fails = int((m["mapper_call"] == "Failed (API refused)").sum())
missed_det = atk[atk["group"] == "Attack worked, missed"]
worked = atk[atk["attack_succeeded"] == 1]
sv = syn[syn["valid_json"] == 1]
syn_ok = int((sv["predicted_category"] == sv["truth"]).sum()) if len(sv) else 0
tiles = []
if len(lv):
    b_atk, b_hl = int((atk["mapper_call"] == "B").sum()), int((hl["mapper_call"] == "B").sum())
    gate_pass = int(((worked["mapper_call"] == "B") & (worked["confidence"] >= data.GATE_THRESHOLD)).sum())
    tiles += [("Attacks confirmed (B)", ui.pct(b_atk, len(atk)), f"{b_atk} of {len(atk)} live attacks", "good"),
              ("Harmless called B", f"{b_hl} / {len(hl)}" if len(hl) else "–",
               "false positives at any confidence" if len(hl) else "no harmless messages in this run",
               ("good" if not b_hl else "bad") if len(hl) else None),
              (f"Pass the gate (≥ {data.GATE_THRESHOLD})", f"{gate_pass} / {len(worked)}", "successful attacks", "accent")]
if len(syn):
    tiles += [("Synthetic accuracy", ui.pct(syn_ok, len(sv)), f"{syn_ok} of {len(sv)} match the answer key", "good")]
ui.kpis(tiles)

FRAMEWORKS = {"ATLAS": ("atlas", "atlas_technique"), "ATT&CK": ("attack", "attck_technique"), "OWASP LLM Top 10": ("owasp_llm", "owasp_category")}
valid = m[m["valid_json"] == 1]
with ui.panel("Browse by technique", "select a technique, then an alert"):
    fwname = st.radio("Framework", list(FRAMEWORKS), horizontal=True, label_visibility="collapsed", key="browse_fw")
    key, col = FRAMEWORKS[fwname]
    pairs = pd.DataFrame([(r.alert_id, i) for r in valid[["alert_id", col]].itertuples(index=False) for i in data.ids(getattr(r, col))],
                         columns=["alert_id", "technique"])
    if pairs.empty:
        st.caption(f"No {fwname} identifiers in this run.")
    else:
        j = pairs.merge(valid[["alert_id", "harmless", "attack_succeeded", "confidence", "source"]], on="alert_id")
        tt = j.groupby("technique").agg(alerts=("alert_id", "nunique"),
                                        synthetic=("source", lambda x: int((x == "synthetic").sum())),
                                        worked=("attack_succeeded", lambda x: int((x == 1).sum())),
                                        harmless=("harmless", "sum"), conf=("confidence", "mean")).reset_index()
        tt["name"] = tt["technique"].map(lambda i: alert_view.technique_label(key, i).split(" · ", 1)[-1] if " · " in alert_view.technique_label(key, i) else "–")
        tt["share"] = tt["alerts"] / len(valid)
        tt = tt.sort_values("alerts", ascending=False).reset_index(drop=True)
        tview = tt[["technique", "name", "alerts", "share", "worked", "harmless", "synthetic", "conf"]].rename(columns={
            "technique": "ID", "name": "Technique", "alerts": "Alerts", "share": "Share of alerts", "worked": "Attacks that worked",
            "synthetic": "Synthetic",
            "harmless": "Harmless", "conf": "Mean confidence"})
        tsel = st.dataframe(tview, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                            key=f"browse_tech_{key}", height=min(38 + 35 * len(tview), 320),
                            column_config={"Share of alerts": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
                                           "Mean confidence": st.column_config.NumberColumn(format="%.2f")})
        if tsel and tsel.selection and tsel.selection.rows:
            tech = tt.iloc[tsel.selection.rows[0]]["technique"]
            ids_ = set(pairs.loc[pairs["technique"] == tech, "alert_id"])
            al = valid[valid["alert_id"].isin(ids_)].sort_values("confidence", ascending=False)
            av = pd.DataFrame({"Alert": al["alert_id"], "Source": al["source"],
                               "Family": al["family"].where(~al["harmless"], "harmless").where(al["source"] == "live", "–"),
                               "Observed outcome": al["group"], "Answer key": al["truth"].fillna("–"),
                               "Mapper category": al["mapper_call"], "Confidence": al["confidence"],
                               "Rationale": al["rationale"].fillna("").str.slice(0, 140)}).reset_index(drop=True)
            st.markdown(f"**{html.escape(alert_view.technique_label(key, tech))}** "
                        f"<span class='muted'>· {len(av):,} alerts · select one to open it</span>", unsafe_allow_html=True)
            asel = st.dataframe(av, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                                key=f"browse_alerts_{key}_{tech}", height=min(38 + 35 * len(av), 320),
                                column_config={"Confidence": st.column_config.NumberColumn(format="%.2f"),
                                               "Alert": st.column_config.NumberColumn(format="%d")})
            if asel and asel.selection and asel.selection.rows:
                alert_view.render(mt, int(av.iloc[asel.selection.rows[0]]["Alert"]), run_id=run)



def live_section():
    order = ["Attack worked, caught", "Attack worked, missed", "Attack failed, caught", "Attack failed, missed",
             "Harmless, flagged", "Harmless, not flagged"]
    cols = ["B", "C", "A", "D", "E", "No attack", "Failed (API refused)"]
    c1, c2 = st.columns([3, 2], gap="medium")
    with c1:
        with ui.panel("Mapper category by observed outcome", "alerts"):
            ct = lv.groupby(["group", "mapper_call"]).size().reset_index(name="n")
            heat = alt.Chart(ct).mark_rect(stroke=ui.PANEL, strokeWidth=2).encode(
                x=alt.X("mapper_call:N", title="Mapper category", sort=cols, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("group:N", title=None, sort=order, axis=alt.Axis(labelLimit=200)),
                color=alt.Color("n:Q", title="Alerts", scale=alt.Scale(range=["#C5E9FA", "#72C6F5", "#429BD1"])),
                tooltip=[alt.Tooltip("group:N", title="Observed outcome"), alt.Tooltip("mapper_call:N", title="Mapper category"),
                         alt.Tooltip("n:Q", title="Alerts", format=",")])
            txt = alt.Chart(ct).mark_text(fontSize=12, fontWeight="bold", color="#0B1220").encode(
                x=alt.X("mapper_call:N", sort=cols), y=alt.Y("group:N", sort=order), text="n:Q",
                tooltip=[alt.Tooltip("group:N", title="Observed outcome"), alt.Tooltip("mapper_call:N", title="Mapper category"),
                         alt.Tooltip("n:Q", title="Alerts", format=",")])
            st.altair_chart(ui.chart(alt.layer(heat, txt), alt.Step(32)), width="stretch")
    with c2:
        with ui.panel("Called B, by attack family"):
            fam = atk.groupby("family")["mapper_call"].agg(total="size", b=lambda s: int((s == "B").sum())).reset_index()
            fam["rate"] = fam["b"] / fam["total"]
            bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=3).encode(
                x=alt.X("rate:Q", title="Called B", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
                y=alt.Y("family:N", title=None, sort="-x"),
                color=alt.Color("family:N", legend=None, scale=alt.Scale(domain=list(ui.FAMILY_COLOR), range=list(ui.FAMILY_COLOR.values()))),
                tooltip=[alt.Tooltip("family:N", title="Family"), alt.Tooltip("total:Q", title="Attacks", format=","),
                         alt.Tooltip("b:Q", title="Called B", format=","), alt.Tooltip("rate:Q", title="Called B", format=".1%")])
            st.altair_chart(ui.chart(bars, 260), width="stretch")


def synthetic_section():
    cats = ["A", "B", "C", "D"]
    pcols = cats + ["E", "No attack", "Failed (API refused)"]
    c1, c2 = st.columns([3, 2], gap="medium")
    with c1, ui.panel("Answer key vs Mapper category", "synthetic alerts"):
        cm = syn.assign(truth=syn["truth"].fillna("–")).groupby(["truth", "mapper_call"]).size().reset_index(name="n")
        cm["match"] = cm["truth"] == cm["mapper_call"]
        heat = alt.Chart(cm).mark_rect(stroke=ui.PANEL, strokeWidth=2).encode(
            x=alt.X("mapper_call:N", title="Mapper category", sort=pcols, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("truth:N", title="Answer key", sort=cats),
            color=alt.condition("datum.match", alt.value(ui.GOOD), alt.value(ui.BAD)),
            tooltip=[alt.Tooltip("truth:N", title="Answer key"), alt.Tooltip("mapper_call:N", title="Mapper category"),
                     alt.Tooltip("n:Q", title="Alerts")])
        txt = alt.Chart(cm).mark_text(fontSize=12, fontWeight="bold", color="#0B1220").encode(
            x=alt.X("mapper_call:N", sort=pcols), y=alt.Y("truth:N", sort=cats), text="n:Q")
        st.altair_chart(ui.chart(alt.layer(heat, txt), alt.Step(40)), width="stretch")
    with c2, ui.panel("Accuracy by category", "valid classifications"):
        pc = sv.groupby("truth").agg(alerts=("alert_id", "size"),
                                     correct=("predicted_category", lambda x: 0)).reset_index()
        pc["correct"] = [int((sv.loc[sv["truth"] == t, "predicted_category"] == t).sum()) for t in pc["truth"]]
        pc["accuracy"] = pc["correct"] / pc["alerts"]
        st.dataframe(pc.rename(columns={"truth": "Category", "alerts": "Alerts", "correct": "Correct", "accuracy": "Accuracy"}),
                     hide_index=True, width="stretch",
                     column_config={"Accuracy": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1)})
    wrong = syn[(syn["valid_json"] != 1) | (syn["predicted_category"] != syn["truth"])]
    with ui.panel("Misclassified synthetic alerts", f"{len(wrong)} alerts · select one to open it"):
        if wrong.empty:
            st.caption("Every synthetic alert in this run matches its answer key.")
        else:
            wv = pd.DataFrame({"Alert": wrong["alert_id"], "Answer key": wrong["truth"].fillna("–"),
                               "Mapper category": wrong["mapper_call"], "Confidence": wrong["confidence"],
                               "Rationale": wrong["rationale"].fillna("").str.slice(0, 160)}).reset_index(drop=True)
            ws = st.dataframe(wv, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                              key="syn_wrong", column_config={"Confidence": st.column_config.NumberColumn(format="%.2f")})
            if ws and ws.selection and ws.selection.rows:
                alert_view.render(mt, int(wv.iloc[ws.selection.rows[0]]["Alert"]), run_id=run)


parts = ([("Live alerts", live_section)] if len(lv) else []) + ([("Synthetic alerts", synthetic_section)] if len(syn) else [])
if len(parts) == 2:
    for tab, (_, fn) in zip(st.tabs([p[0] for p in parts]), parts):
        with tab:
            fn()
elif parts:
    parts[0][1]()

SEV = {"Critical": ui.SEV_COLOR["Critical"], "High": ui.SEV_COLOR["High"], "Medium": ui.SEV_COLOR["Medium"],
       "Low": ui.SEV_COLOR["Low"], "Informational": ui.SEV_COLOR["Info"]}


def coverage_html(mx: dict) -> tuple[str, int]:
    """Compact framework view: one card per tactic with at least one assigned technique."""
    cards, tallest = [], 0
    for tac in mx["tactics"]:
        rows = [r for r in mx["columns"].get(tac["id"], []) if r["severity"] or r["child_severity"]]
        tac_sev = mx["tactic_hits"].get(tac["id"])
        if not rows and not tac_sev:
            continue
        items = []
        for r in rows:
            c = SEV.get(r["severity"] or r["child_severity"], ui.MUTED)
            n = len(r["alert_ids"])
            items.append(f'<div class="cv-t" style="--s:{c}"><span class="id">{html.escape(r["id"])}</span> '
                         f'{html.escape(r["name"])}<span class="n">{n or ""}</span></div>')
            for sub in r["subtechniques"]:
                if sub["severity"]:
                    items.append(f'<div class="cv-t sub" style="--s:{SEV.get(sub["severity"], ui.MUTED)}"><span class="id">'
                                 f'{html.escape(sub["id"])}</span> {html.escape(sub["name"])}<span class="n">{len(sub["alert_ids"])}</span></div>')
        if tac_sev and not rows:
            items.append(f'<div class="cv-t" style="--s:{SEV.get(tac_sev, ui.MUTED)}">tactic assigned directly</div>')
        tallest = max(tallest, len(items))
        cards.append(f'<div class="cv-c"><div class="cv-h">{html.escape(tac["name"])}</div>{"".join(items)}</div>')
    return '<div class="cv">' + "".join(cards) + "</div>", tallest


CV_CSS = f"""<style>
.cv {{display:grid; grid-template-columns:repeat(auto-fill,minmax(230px,1fr)); gap:10px; margin-bottom:10px;}}
.cv-c {{background:{ui.PANEL2}; border:1px solid {ui.BORDER}; border-radius:8px; padding:10px 12px;}}
.cv-h {{font-size:.72rem; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:{ui.MUTED}; margin-bottom:6px;}}
.cv-t {{border-left:3px solid var(--s); padding:4px 8px; margin:4px 0; font-size:.82rem; display:flex; gap:6px; align-items:baseline;
        background:{ui.BG}66; border-radius:4px;}}
.cv-t.sub {{margin-left:14px; font-size:.78rem;}}
.cv-t .id {{color:{ui.MUTED}; font-variant-numeric:tabular-nums; white-space:nowrap;}}
.cv-t .n {{margin-left:auto; font-weight:700; font-variant-numeric:tabular-nums;}}
.cv-o {{display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:8px; margin-bottom:10px;}}
.cv-o div {{border:1px solid {ui.BORDER}; border-top:3px solid var(--s); border-radius:6px; padding:8px 10px; font-size:.78rem; background:{ui.PANEL2};}}
.cv-o div.off {{opacity:.4;}}
.cv-o b {{display:block; font-size:1.05rem;}}
</style>"""

with ui.panel("Framework coverage", "techniques this run assigned · count = alerts · colour = highest severity"):
    fw = st.radio("Framework", ["ATLAS", "ATT&CK", "OWASP LLM Top 10"], horizontal=True, label_visibility="collapsed", key="cov_fw")
    full = None
    try:
        from mapper import matrix_data, matrix_render
        conn = data.connect()
        try:
            st.markdown(CV_CSS, unsafe_allow_html=True)
            if fw == "OWASP LLM Top 10":
                cards = matrix_data.build_owasp_strip(conn, run_id=run)
                st.markdown('<div class="cv-o">' + "".join(
                    f'<div class="{"" if c["severity"] else "off"}" style="--s:{SEV.get(c["severity"], ui.BORDER)}">'
                    f'<b>{len(c["alert_ids"]) or "–"}</b>{html.escape(c["id"])} {html.escape(c["name"])}</div>' for c in cards)
                    + "</div>", unsafe_allow_html=True)
                full = (matrix_render.render_owasp_strip_html(cards), 260)
            else:
                mx = matrix_data.build_matrix(conn, "atlas" if fw == "ATLAS" else "attack", run_id=run)
                body, tallest = coverage_html(mx)
                if tallest:
                    st.markdown(body, unsafe_allow_html=True)
                else:
                    st.caption(f"No {fw} identifiers in this run.")
                full = (matrix_render.render_matrix_html(mx, hide_untouched=True), 150 + 62 * max(tallest, 1))
        finally:
            conn.close()
    except ImportError as e:
        st.caption(f"Framework view unavailable ({e}).")

with ui.details():
    if len(lv):
        ui.kpis([
            ("Caught what detection missed", ui.pct(int((missed_det["mapper_call"] == "B").sum()), len(missed_det)),
             "missed successful attacks called B", "accent"),
            ("Failed classifications", f"{fails}", "the API refused the content", "warn" if fails else None),
        ])
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
    if full:
        with ui.panel(f"Full {fw} matrix", "official layout, untouched techniques hidden"):
            try:
                st.iframe(full[0], height=full[1])
            except Exception:  # noqa: BLE001  older Streamlit
                import streamlit.components.v1 as components
                components.html(full[0], height=full[1], scrolling=True)
    if len(lv):
        c1, c2 = st.columns(2, gap="medium")
        with c1:
            with ui.panel("Confidence distribution", "valid classifications"):
                v = lv[lv["valid_json"] == 1].copy()
                v["kind"] = v["harmless"].map({True: "Harmless", False: "Attack"})
                hist = alt.Chart(v).mark_bar(opacity=0.85).encode(
                    x=alt.X("confidence:Q", bin=alt.Bin(step=0.05), title="Mapper confidence"),
                    y=alt.Y("count():Q", title="Alerts", stack=None),
                    color=alt.Color("kind:N", title=None, scale=alt.Scale(domain=["Attack", "Harmless"], range=[ui.ACCENT, ui.PURPLE])),
                    tooltip=[alt.Tooltip("kind:N", title="Event type"), alt.Tooltip("count():Q", title="Alerts", format=",")])
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
                    tooltip=[alt.Tooltip("threshold:Q", title="Minimum confidence", format=".2f"),
                             alt.Tooltip("series:N", title="Series"), alt.Tooltip("n:Q", title="Alerts passing", format=",")])
                rule = alt.Chart(pd.DataFrame({"x": [data.GATE_THRESHOLD]})).mark_rule(strokeDash=[4, 4], color=ui.WARN).encode(x="x:Q")
                st.altair_chart(ui.chart_legend(ui.chart(alt.layer(line, rule), 230), columns=1), width="stretch")
