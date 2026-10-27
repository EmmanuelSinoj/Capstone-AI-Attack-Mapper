import altair as alt
import streamlit as st

import data
import ui

st.title("Attack campaigns")
ui.intro("Every attack round run against the test chatbot: which tool, which system-prompt version, how big it was and how "
         "often the attacks worked. \"Worked\" is the attack tool's own grading of the chatbot's reply.")

mt = data.db_mtime()
rt = data.rounds_table(mt)
if rt.empty:
    ui.no_data("No attack rounds in the alert store yet.")
    st.stop()

attack_rounds = rt[rt["tool"].isin(["Garak", "PyRIT"])]
ui.kpis([
    ("Attack rounds", f"{len(attack_rounds)}", f"{int(attack_rounds['invalid'].sum())} with unreliable detector flags", None),
    ("Attack requests", f"{int(attack_rounds['requests'].sum()):,}", "prompts sent to the chatbot", None),
    ("Attacks that worked", ui.pct(attack_rounds["worked"].sum(), attack_rounds["graded"].sum()),
     f"{int(attack_rounds['worked'].sum()):,} of {int(attack_rounds['graded'].sum()):,} graded requests", "bad"),
    ("Harmless rounds", f"{int((rt['tool'] == 'Harmless messages').sum())}", "normal customer messages, for false alarms", None),
])

st.subheader("Rounds")
show = rt.reset_index().rename(columns={"run_id": "Round", "tool": "Tool", "prompt_version": "Prompt version", "started": "Started (UTC)",
                                        "minutes": "Minutes", "requests": "Requests", "success_rate": "Attacks worked"})
show["Status"] = show["invalid"].map(lambda x: "Detector failed" if x else "Valid")
show.loc[show["Tool"] == "Harmless messages", "Attacks worked"] = None
st.dataframe(show[["Round", "Tool", "Prompt version", "Started (UTC)", "Minutes", "Requests", "Attacks worked", "Status"]],
             hide_index=True, width="stretch",
             column_config={"Attacks worked": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1),
                            "Started (UTC)": st.column_config.DatetimeColumn(format="DD MMM, HH:mm")})
st.caption("Rounds marked \"Detector failed\" keep valid attack grades, but their detector flags are left out of the Detection page.")

st.subheader("What worked, by attack family")
choice = st.selectbox("Round", ["All attack rounds"] + list(attack_rounds.index),
                      format_func=lambda r: r if r == "All attack rounds" else f"{r} · prompt v{rt.loc[r, 'prompt_version']}")
df = data.live_rows(mt)
df = df[df["kind"].isin(["garak", "pyrit"]) & ~df["harmless"]]
if choice != "All attack rounds":
    df = df[df["run_id"] == choice]
fam = (df[df["attack_succeeded"].notna()].groupby("family")
       .agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index())
fam["rate"] = fam["worked"] / fam["requests"]
c1, c2 = st.columns([3, 2])
with c1:
    bars = alt.Chart(fam).mark_bar(cornerRadiusEnd=4, color=ui.BAD).encode(
        x=alt.X("rate:Q", title="Share of attacks that worked", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("family:N", title=None, sort="-x"),
        tooltip=[alt.Tooltip("family:N", title="Family"), alt.Tooltip("requests:Q", title="Requests"),
                 alt.Tooltip("worked:Q", title="Worked"), alt.Tooltip("rate:Q", title="Rate", format=".1%")])
    st.altair_chart(ui.chart(bars, 60 * max(len(fam), 2)), width="stretch")
with c2:
    st.dataframe(fam.rename(columns={"family": "Family", "requests": "Requests", "worked": "Worked", "rate": "Rate"}),
                 hide_index=True, width="stretch", column_config={"Rate": st.column_config.NumberColumn(format="percent")})
st.caption("Families: promptinject = instruction hijacking; dan = jailbreak personas; encoding = payloads hidden in encodings; "
           "pyrit = scripted objectives such as system-prompt extraction.")

with st.expander("Probes in this selection"):
    pr = (df[df["attack_succeeded"].notna()].groupby("probe_id")
          .agg(requests=("id", "size"), worked=("attack_succeeded", "sum")).reset_index().sort_values("worked", ascending=False))
    pr["rate"] = pr["worked"] / pr["requests"]
    st.dataframe(pr.rename(columns={"probe_id": "Probe", "requests": "Requests", "worked": "Worked", "rate": "Rate"}), hide_index=True,
                 width="stretch", column_config={"Rate": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1)})
