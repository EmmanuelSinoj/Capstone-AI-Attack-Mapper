import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** Every request sent to the test chatbot in the live attack path (Garak and PyRIT attack rounds,
plus the harmless customer messages), and where each part of the pipeline stands.

**Event severity**
- **Critical**: the attack worked and the detector missed it.
- **High**: the attack worked and the detector caught it.
- **Medium**: the attack failed and the detector still flagged it.
- **Low**: the attack failed and was not flagged.
- **False alarm**: a harmless customer message was flagged.

**Data rules.** "Worked" is the attack tool's own grading of the chatbot's reply. Rounds where the detector failed are left out
of the detection numbers (their attack grades are kept on Attack campaigns). Mapper numbers come from the latest live
classification run; the held-out accuracy is the Model Selection Pilot result (22 of 24 unseen synthetic alerts).
The time range in the sidebar filters the events on this page.
"""

ui.header("Overview", "Security events from the live attack path and the state of each pipeline stage.", ABOUT, "Situation")

mt = data.db_mtime()
df = data.live_rows(mt)
if df.empty:
    ui.no_data("No live data in the alert store yet.")
    st.stop()

valid = data.window(df[df["kind"].isin(["garak", "pyrit", "benign"]) & ~df["invalid_round"]])
s = data.detection_summary(valid)
missed = s["worked"] - s["worked_caught"]

runs = data.mapper_runs(mt)
runs = runs[runs["results"] >= 20] if not runs.empty else runs
mres = data.mapper_results(mt, runs.iloc[0]["run_id"]) if not runs.empty else pd.DataFrame()
atk = mres[~mres["harmless"]] if not mres.empty else mres
hl = mres[mres["harmless"]] if not mres.empty else mres
mapper_b = int((atk["mapper_call"] == "B").sum()) if not mres.empty else 0
mapper_harm_b = int((hl["mapper_call"] == "B").sum()) if not mres.empty else 0

versions = data.prompt_versions()
decisions = [h for h in data.hardening_history() if h.get("decision")]
latest = data.latest_fresh_decision(decisions)
n_pb = len(data.playbooks(mt))

stages = [
    ("Attack", f"{s['attacks_sent']:,}", f"requests sent; {s['worked']:,} worked"),
    ("Detect", ui.pct(s["worked_caught"], s["worked"]), f"of successful attacks caught; {missed:,} missed"),
    ("Classify", ui.pct(mapper_b, len(atk)) if len(atk) else "–", f"of {len(atk)} sampled live attacks called B" if len(atk) else "no live Mapper run"),
    ("Harden", f"v{versions[-1]['version']}" if versions else "–", f"fresh-round decision: {latest['decision']}" if latest else "fresh-round decision pending"),
    ("Respond", f"{n_pb:,}", "alerts with a defense playbook"),
]
st.markdown('<div class="flow">' + '<span class="arrow">›</span>'.join(
    f'<div class="stage"><div class="t">{t}</div><div class="n">{n}</div><div class="d">{d}</div></div>' for t, n, d in stages)
    + "</div>", unsafe_allow_html=True)

ui.kpis([
    ("Attacks that worked", ui.pct(s["worked"], s["worked"] + s["failed"]), f"{s['worked']:,} of {s['worked'] + s['failed']:,} graded requests", "bad"),
    ("Critical: missed", f"{missed:,}", "worked and raised no alert", "bad" if missed else "good"),
    ("False alarms", ui.pct(s["harmless_flagged"], s["harmless"]), f"{s['harmless_flagged']} of {s['harmless']:,} harmless messages",
     "good" if s["harmless"] and s["harmless_flagged"] / s["harmless"] < 0.01 else "warn"),
    ("Mapper false positives", f"{mapper_harm_b} / {len(hl)}" if len(hl) else "–", "harmless messages called B", "good" if not mapper_harm_b else "bad"),
    ("Mapper accuracy", "91.7%", "held-out, 22 of 24 synthetic alerts", "accent"),
])

c1, c2 = st.columns([2, 1])
with c1:
    with ui.panel("Security events over time", f"{len(valid):,} events"):
        t = valid.dropna(subset=["ts"]).copy()
        t["hour"] = t["ts"].dt.tz_convert(None).dt.floor("h")
        g = t.groupby(["hour", "severity"]).size().reset_index(name="n")
        g["slot"] = g["hour"].dt.strftime("%d %b %H:00")
        bars = alt.Chart(g).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X("slot:O", title="Hour (UTC)", sort=sorted(g["slot"].unique(), key=lambda x: pd.to_datetime(x, format="%d %b %H:%M")),
                    axis=alt.Axis(labelAngle=-35)),
            y=alt.Y("n:Q", title="Events", stack="zero"),
            color=alt.Color("severity:N", title=None, sort=ui.SEVERITY,
                            scale=alt.Scale(domain=ui.SEVERITY, range=[ui.SEV_COLOR[x] for x in ui.SEVERITY])),
            order=alt.Order("sev_rank:Q"),
            tooltip=["slot", "severity", alt.Tooltip("n:Q", format=",")],
        ).transform_calculate(sev_rank=f"indexof({ui.SEVERITY}, datum.severity)")
        st.altair_chart(ui.chart(bars, 250), width="stretch")
with c2:
    with ui.panel("Events by severity"):
        sc = valid["severity"].value_counts().reindex(ui.SEVERITY).dropna().rename_axis("severity").reset_index(name="n")
        donut = alt.Chart(sc).mark_arc(innerRadius=50, outerRadius=88, stroke=ui.PANEL, strokeWidth=2).encode(
            theta="n:Q", color=alt.Color("severity:N", title=None, sort=ui.SEVERITY,
                                         scale=alt.Scale(domain=ui.SEVERITY, range=[ui.SEV_COLOR[x] for x in ui.SEVERITY])),
            tooltip=["severity", alt.Tooltip("n:Q", format=",")])
        st.altair_chart(ui.chart(donut, 270), width="stretch")

c1, c2, c3 = st.columns(3)
with c1:
    with ui.panel("Top attack families"):
        a = valid[~valid["harmless"] & valid["attack_succeeded"].notna()].copy()
        a["wc"] = a["caught"] & (a["attack_succeeded"] == 1)
        fam = a.groupby("family").agg(Requests=("id", "size"), Worked=("attack_succeeded", "sum"), Caught=("wc", "sum")).reset_index()
        fam["Worked %"] = 100 * fam["Worked"] / fam["Requests"]
        fam["Detected %"] = (100 * fam["Caught"] / fam["Worked"]).where(fam["Worked"] > 0)
        st.dataframe(fam.sort_values("Requests", ascending=False).rename(columns={"family": "Family"})
                     [["Family", "Requests", "Worked %", "Detected %"]], hide_index=True, width="stretch",
                     column_config={"Worked %": st.column_config.NumberColumn(format="%.1f%%"),
                                    "Detected %": st.column_config.NumberColumn(format="%.1f%%")})
with c2:
    with ui.panel("Top detection signals", "flagged events"):
        flagged = valid[valid["caught"]]
        det = pd.DataFrame([data.parse_detector(d) for d in flagged["detector"]])
        sig = []
        if not det.empty:
            for r in det.loc[det["heuristic_fired"], "heuristic_rule"]:
                sig += [f"rule: {x.strip()}" for x in r.split(",") if x.strip()]
            sig += [f"judge: {x}" for x in det.loc[det["judge_fired"], "judge_label"]]
        top = pd.Series(sig).value_counts().head(8).rename_axis("Signal").reset_index(name="Events") if sig else pd.DataFrame()
        if top.empty:
            st.caption("Nothing flagged in this range.")
        else:
            st.dataframe(top, hide_index=True, width="stretch")
with c3:
    with ui.panel("Needs attention"):
        if missed:
            ui.alert("Critical", f"{missed:,} successful attacks were not detected.", "Review them on Detection.")
        if not mres.empty:
            enc = atk[atk["family"] == "encoding"]
            if len(enc):
                ui.alert("Medium", "Encoded attacks are the Mapper's weak spot.",
                         f"{int((enc['mapper_call'] == 'B').sum())} of {len(enc)} called B.")
        if latest:
            ui.alert("Info" if latest["decision"] == "ACCEPT" else "Medium", f"Hardening decision on fresh rounds: {latest['decision']}.",
                     f"v{latest.get('candidate')} vs v{latest.get('parent')}, target families: {data.decision_test(latest)['targets']}.")
        else:
            ui.alert("Medium", "No hardening decision on fresh rounds yet.",
                     "Replay tests on seen prompts are listed on Auto-hardening." if decisions else "")
        if not n_pb:
            ui.alert("Low", "No defense playbooks yet.", "They appear once playbook generation has run.")
        if s["harmless_flagged"]:
            ui.alert("False alarm", f"{s['harmless_flagged']} harmless messages flagged.", "See Detection.")

with ui.panel("Recent critical and high events", "attacks that worked"):
    rec = valid[valid["severity"].isin(["Critical", "High"])].sort_values("ts", ascending=False).head(15)
    if rec.empty:
        st.caption("None in this range.")
    else:
        view = pd.DataFrame({"Time (UTC)": rec["ts"].dt.strftime("%d %b %H:%M:%S"), "Severity": rec["severity"], "Alert": rec["id"],
                             "Family": rec["family"], "Probe": rec["probe_id"], "Round": rec["run_id"],
                             "Detector": rec["caught"].map({True: "flagged", False: "missed"})})
        st.dataframe(ui.sev_style(view), hide_index=True, width="stretch")
        st.caption("Open any alert id in the Alert explorer.")
