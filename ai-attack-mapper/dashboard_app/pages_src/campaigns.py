import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** Every round run against the test chatbot: which tool sent it, which system-prompt version it
attacked, how large it was and how often the attacks worked.

- **Worked** is the attack tool's own grading of the chatbot's reply (Garak's detectors; PyRIT's scorer).
- **Harmless rounds** send normal customer messages; they are used for false alarms and refusal checks, not for attack success.
- Rounds marked **Detector failed** keep their attack grades, but their detector flags are left out of the Detection page.

**Attack families.** promptinject = instruction hijacking; dan = jailbreak personas; encoding = payloads hidden in encodings;
pyrit = scripted objectives such as system-prompt extraction.
"""

ui.header("Attack campaigns", "Attack and harmless rounds run against the test chatbot.", ABOUT, "Investigate")

mt = data.db_mtime()
rt = data.rounds_table(mt)
if rt.empty:
    ui.no_data("No attack rounds in the alert store yet.")
    st.stop()
tr = st.session_state.get("time_range")
if tr and len(tr) == 2:
    rt = rt[(rt["started"].dt.date >= tr[0]) & (rt["started"].dt.date <= tr[1])]

attack_rounds = rt[rt["tool"].isin(["Garak", "PyRIT"])]
ui.kpis([
    ("Attack rounds", f"{len(attack_rounds)}", f"{int(attack_rounds['invalid'].sum())} with unreliable detector flags", "accent"),
    ("Attack requests", f"{int(attack_rounds['requests'].sum()):,}", "prompts sent to the chatbot", None),
    ("Attacks that worked", ui.pct(attack_rounds["worked"].sum(), attack_rounds["graded"].sum()),
     f"{int(attack_rounds['worked'].sum()):,} of {int(attack_rounds['graded'].sum()):,} graded requests", "bad"),
    ("Harmless rounds", f"{int((rt['tool'] == 'Harmless messages').sum())}",
     f"{int(rt.loc[rt['tool'] == 'Harmless messages', 'requests'].sum()):,} customer messages", None),
    ("Prompt versions attacked", f"{rt['prompt_version'].nunique()}", ", ".join(f"v{v}" for v in sorted(rt["prompt_version"].unique())), None),
])

df = data.window(data.live_rows(mt))
df = df[df["kind"].isin(["garak", "pyrit"]) & ~df["harmless"] & df["attack_succeeded"].notna()]

c1, c2 = st.columns([3, 2])
with c1:
    with ui.panel("Round timeline", "requests per round"):
        tl = rt.reset_index()
        tl["label"] = tl["run_id"]
        bars = alt.Chart(tl).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X("label:N", title=None, sort=alt.EncodingSortField("started"), axis=alt.Axis(labelAngle=-40, labelLimit=180, labelOverlap=False, labelFontSize=10)),
            y=alt.Y("requests:Q", title="Requests"),
            color=alt.Color("tool:N", title=None, scale=alt.Scale(domain=["Garak", "PyRIT", "Harmless messages"],
                                                                range=[ui.ACCENT, ui.GOOD, "#64748B"])),
            tooltip=[alt.Tooltip("run_id:N", title="Round"), "tool", alt.Tooltip("prompt_version:N", title="Prompt"),
                     alt.Tooltip("started:T", title="Started", format="%d %b %H:%M"), alt.Tooltip("requests:Q", format=","),
                     alt.Tooltip("success_rate:Q", title="Worked", format=".1%")])
        st.altair_chart(ui.chart(bars, 270), width="stretch")
with c2:
    with ui.panel("Success rate by family and round"):
        hm = df.groupby(["run_id", "family"]).agg(n=("id", "size"), w=("attack_succeeded", "sum")).reset_index()
        hm["rate"] = hm["w"] / hm["n"]
        heat = alt.Chart(hm).mark_rect(stroke=ui.PANEL, strokeWidth=2).encode(
            x=alt.X("family:N", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("run_id:N", title=None, axis=alt.Axis(labelLimit=180)),
            color=alt.Color("rate:Q", title="Worked", scale=alt.Scale(scheme="orangered", domain=[0, 1]), legend=alt.Legend(format="%")),
            tooltip=["run_id", "family", alt.Tooltip("n:Q", title="Requests", format=","), alt.Tooltip("rate:Q", title="Worked", format=".1%")])
        text = alt.Chart(hm).mark_text(fontSize=11, color="#0B1220", fontWeight="bold").encode(
            x="family:N", y="run_id:N", text=alt.Text("rate:Q", format=".0%"))
        st.altair_chart(ui.chart(alt.layer(heat, text), alt.Step(26)), width="stretch")

with ui.panel("Rounds", f"{len(rt)} rounds"):
    show = rt.reset_index().rename(columns={"run_id": "Round", "tool": "Tool", "prompt_version": "Prompt version", "started": "Started (UTC)",
                                            "minutes": "Minutes", "requests": "Requests", "success_rate": "Attacks worked"})
    show["Status"] = show["invalid"].map(lambda x: "Detector failed" if x else "Valid")
    show.loc[show["Tool"] == "Harmless messages", "Attacks worked"] = None
    st.dataframe(show[["Round", "Tool", "Prompt version", "Started (UTC)", "Minutes", "Requests", "Attacks worked", "Status"]],
                 hide_index=True, width="stretch",
                 column_config={"Attacks worked": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
                                "Started (UTC)": st.column_config.DatetimeColumn(format="DD MMM, HH:mm")})

choice = st.selectbox("Round for the family and probe breakdown", ["All attack rounds"] + list(attack_rounds.index),
                      format_func=lambda r: r if r == "All attack rounds" else f"{r} · prompt v{rt.loc[r, 'prompt_version']}")
sel = df if choice == "All attack rounds" else df[df["run_id"] == choice]
fam = sel.groupby("family").agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index()
fam["rate"] = fam["worked"] / fam["requests"]
c1, c2 = st.columns([2, 3])
with c1:
    with ui.panel("What worked, by attack family"):
        bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=3).encode(
            x=alt.X("rate:Q", title="Share that worked", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
            y=alt.Y("family:N", title=None, sort="-x"),
            color=alt.Color("family:N", legend=None, scale=alt.Scale(domain=list(ui.FAMILY_COLOR), range=list(ui.FAMILY_COLOR.values()))),
            tooltip=[alt.Tooltip("family:N", title="Family"), alt.Tooltip("requests:Q", title="Requests", format=","),
                     alt.Tooltip("worked:Q", title="Worked", format=","), alt.Tooltip("rate:Q", title="Rate", format=".1%")])
        st.altair_chart(ui.chart(bars, alt.Step(34)), width="stretch")
with c2:
    with ui.panel("Top probes", "by successful attacks"):
        pr = (sel.groupby("probe_id").agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index()
              .sort_values("worked", ascending=False))
        pr["rate"] = pr["worked"] / pr["requests"]
        st.dataframe(pr.rename(columns={"probe_id": "Probe", "requests": "Requests", "worked": "Worked", "rate": "Rate"}), hide_index=True,
                     width="stretch", height=260,
                     column_config={"Rate": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1)})
