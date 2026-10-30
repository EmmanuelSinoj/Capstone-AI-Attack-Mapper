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

**Sessions** group the Garak, PyRIT and harmless rounds run together (same date and suffix, e.g. garak_20261005_v6-4,
pyrit_20261005_v6-4 and benign_20261005_v6-4 form session 20261005_v6-4). The sidebar prompt-version filter applies.

**Reading the results.** Lower attack success is better. The prompt version each round attacked is in the Rounds table.

**Details** holds the top probes for the selected round.
"""

ui.header("Attack campaigns", "Attack rounds and harmless-message tests against the chatbot.", ABOUT, "Investigate")

mt = data.db_mtime()
rt = data.rounds_table(mt)
if rt.empty:
    ui.no_data("No attack rounds in the alert store yet.")
    st.stop()
rt = data.filter_rounds(rt)
if rt.empty:
    ui.no_data("No rounds match the sidebar filters.")
    st.stop()
ss = data.sessions_table(rt)

attack_rounds = rt[rt["tool"].isin(["Garak", "PyRIT"])]
ui.scope(f"{len(ss)} sessions, {len(rt)} rounds", data.scope_versions() if st.session_state.get("prompt_versions")
         else "prompt " + ", ".join(f"v{v}" for v in sorted(rt["prompt_version"].unique())), data.scope_dates())
ui.kpis([
    ("Attack rounds", f"{len(attack_rounds)}", f"{int(attack_rounds['invalid'].sum())} with unreliable detector flags", "accent"),
    ("Attack requests", f"{int(attack_rounds['requests'].sum()):,}", "prompts sent to the chatbot", None),
    ("Attacks that worked", ui.pct(attack_rounds["worked"].sum(), attack_rounds["graded"].sum()),
     f"{int(attack_rounds['worked'].sum()):,} of {int(attack_rounds['graded'].sum()):,} graded requests", "bad"),
    ("Harmless rounds", f"{int((rt['tool'] == 'Harmless messages').sum())}",
     f"{int(rt.loc[rt['tool'] == 'Harmless messages', 'requests'].sum()):,} customer messages", None),
])

df = data.window(data.live_rows(mt))
df = df[df["kind"].isin(["garak", "pyrit"]) & ~df["harmless"] & df["attack_succeeded"].notna()]

c1, c2 = st.columns([3, 2], gap="medium")
with c1:
    with ui.panel("Round timeline", "requests per round"):
        tl = rt.reset_index()
        tl["label"] = tl["run_id"]
        bars = alt.Chart(tl).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X("label:N", title=None, sort=alt.EncodingSortField("started"), axis=alt.Axis(labelAngle=-40, labelLimit=180, labelOverlap=False, labelFontSize=10)),
            y=alt.Y("requests:Q", title="Requests"),
            color=alt.Color("tool:N", title=None, scale=alt.Scale(domain=["Garak", "PyRIT", "Harmless messages"],
                                                                range=[ui.ACCENT, ui.GOOD, "#64748B"])),
            tooltip=[alt.Tooltip("run_id:N", title="Round"), alt.Tooltip("tool:N", title="Tool"), alt.Tooltip("prompt_version:N", title="Prompt"),
                     alt.Tooltip("started:T", title="Started (UTC)", format="%d %b %H:%M"), alt.Tooltip("requests:Q", title="Requests", format=","),
                     alt.Tooltip("success_rate:Q", title="Worked", format=".1%")])
        st.altair_chart(ui.chart(bars, 200), width="stretch")
with c2:
    with ui.panel("Success rate by family and round"):
        hm = df.groupby(["run_id", "family"]).agg(n=("id", "size"), w=("attack_succeeded", "sum")).reset_index()
        hm["rate"] = hm["w"] / hm["n"]
        heat = alt.Chart(hm).mark_rect(stroke=ui.PANEL, strokeWidth=2).encode(
            x=alt.X("family:N", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("run_id:N", title=None, axis=alt.Axis(labelLimit=180)),
            color=alt.Color("rate:Q", title="Worked", scale=alt.Scale(range=["#F4DDC1", "#F7B37D", "#F28572"], domain=[0, 1]), legend=alt.Legend(format="%")),
            tooltip=[alt.Tooltip("run_id:N", title="Round"), alt.Tooltip("family:N", title="Family"), alt.Tooltip("n:Q", title="Requests", format=","), alt.Tooltip("rate:Q", title="Worked", format=".1%")])
        text = alt.Chart(hm).mark_text(fontSize=11, color="#0B1220", fontWeight="bold").encode(
            x="family:N", y="run_id:N", text=alt.Text("rate:Q", format=".0%"),
            tooltip=[alt.Tooltip("run_id:N", title="Round"), alt.Tooltip("family:N", title="Family"),
                     alt.Tooltip("n:Q", title="Requests", format=","), alt.Tooltip("rate:Q", title="Worked", format=".1%")])
        st.altair_chart(ui.chart(alt.layer(heat, text), alt.Step(40)), width="stretch")

with ui.panel("Sessions", f"{len(ss)} sessions · Garak, PyRIT and harmless rounds run together"):
    sv = ss.reset_index().rename(columns={"session": "Session", "rounds": "Rounds", "tools": "Tools", "prompt_version": "Prompt version",
                                          "started": "Started (UTC)", "attack_requests": "Attack requests", "success_rate": "Attacks worked",
                                          "harmless": "Harmless messages"})
    sv["Status"] = sv["invalid"].map(lambda x: "Detector failed in a round" if x else "Valid")
    st.dataframe(sv[["Session", "Rounds", "Tools", "Prompt version", "Started (UTC)", "Attack requests", "Attacks worked",
                     "Harmless messages", "Status"]], hide_index=True, width="stretch",
                 column_config={"Attacks worked": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
                                "Started (UTC)": st.column_config.DatetimeColumn(format="DD MMM, HH:mm"),
                                "Attack requests": st.column_config.NumberColumn(format="%d"),
                                "Harmless messages": st.column_config.NumberColumn(format="%d")})

with ui.panel("Rounds", f"{len(rt)} rounds"):
    show = rt.reset_index().rename(columns={"run_id": "Round", "tool": "Tool", "prompt_version": "Prompt version", "started": "Started (UTC)",
                                            "minutes": "Minutes", "requests": "Requests", "success_rate": "Attacks worked"})
    show["Status"] = show["invalid"].map(lambda x: "Detector failed" if x else "Valid")
    show.loc[show["Tool"] == "Harmless messages", "Attacks worked"] = None
    show = show.rename(columns={"session": "Session"})
    st.dataframe(show[["Round", "Session", "Tool", "Prompt version", "Started (UTC)", "Minutes", "Requests", "Attacks worked", "Status"]],
                 hide_index=True, width="stretch",
                 column_config={"Attacks worked": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
                                "Started (UTC)": st.column_config.DatetimeColumn(format="DD MMM, HH:mm")})

atk_sessions = list(ss[ss["attack_requests"] > 0].index)
opts = ["All attack rounds"] + [f"session:{x}" for x in atk_sessions] + list(attack_rounds.index)
choice = st.selectbox("Family and probe breakdown", opts,
                      format_func=lambda r: r if r == "All attack rounds" else (f"Session {r[8:]} (all tools)" if r.startswith("session:")
                                                                                else f"Round {r} · prompt v{rt.loc[r, 'prompt_version']}"))
sel = df if choice == "All attack rounds" else (df[df["session"] == choice[8:]] if choice.startswith("session:") else df[df["run_id"] == choice])
fam = sel.groupby("family").agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index()
fam["rate"] = fam["worked"] / fam["requests"]
with ui.panel("Attack success by family"):
    bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=3).encode(
        x=alt.X("rate:Q", title="Share that worked", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("family:N", title=None, sort="-x"),
        color=alt.Color("family:N", legend=None, scale=alt.Scale(domain=list(ui.FAMILY_COLOR), range=list(ui.FAMILY_COLOR.values()))),
        tooltip=[alt.Tooltip("family:N", title="Family"), alt.Tooltip("requests:Q", title="Requests", format=","),
                 alt.Tooltip("worked:Q", title="Worked", format=","), alt.Tooltip("rate:Q", title="Rate", format=".1%")])
    st.altair_chart(ui.chart(bars, alt.Step(34)), width="stretch")

with ui.details():
    with ui.panel("Top probes", "by successful attacks"):
        pr = (sel.groupby("probe_id").agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index()
              .sort_values("worked", ascending=False))
        pr["rate"] = pr["worked"] / pr["requests"]
        st.dataframe(pr.rename(columns={"probe_id": "Probe", "requests": "Requests", "worked": "Worked", "rate": "Rate"}), hide_index=True,
                     width="stretch", height=260,
                     column_config={"Rate": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1)})
