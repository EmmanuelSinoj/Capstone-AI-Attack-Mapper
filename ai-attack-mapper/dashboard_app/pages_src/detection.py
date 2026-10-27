import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

st.title("Detection")
ui.intro("Did the two-layer detector (pattern rules, then the Prompt-Guard judge model) flag the attacks, and how often did it "
         "raise false alarms on normal customer messages? The key number is the share of <b>successful</b> attacks it caught.")

mt = data.db_mtime()
df = data.live_rows(mt)
if df.empty:
    ui.no_data("No live data in the alert store yet.")
    st.stop()
df = df[df["kind"].isin(["garak", "pyrit", "benign"])]
rt = data.rounds_table(mt)
valid_rounds = [r for r in rt.index if not rt.loc[r, "invalid"]]
attack_rounds = [r for r in valid_rounds if rt.loc[r, "tool"] in ("Garak", "PyRIT")]
opts = ["All valid rounds"] + valid_rounds
choice = st.selectbox("Rounds", opts, index=0,
                      format_func=lambda r: r if r == opts[0] else f"{r} · {rt.loc[r, 'tool']} · prompt v{rt.loc[r, 'prompt_version']}")
sel = df[~df["invalid_round"]] if choice == opts[0] else df[df["run_id"] == choice]
s = data.detection_summary(sel)
missed = s["worked"] - s["worked_caught"]

ui.kpis([
    ("Caught: successful attacks", ui.pct(s["worked_caught"], s["worked"]), f"{s['worked_caught']:,} of {s['worked']:,}", "good"),
    ("Missed: successful attacks", f"{missed:,}", "attacks that worked and were not flagged", "bad" if missed else "good"),
    ("Caught: failed attempts", ui.pct(s["failed_caught"], s["failed"]), f"{s['failed_caught']:,} of {s['failed']:,}", None),
    ("False alarms", ui.pct(s["harmless_flagged"], s["harmless"]) if s["harmless"] else "–",
     f"{s['harmless_flagged']} of {s['harmless']:,} harmless messages" if s["harmless"] else "no harmless messages in this selection",
     "good" if not s["harmless_flagged"] else "warn"),
])
if s["ungraded"]:
    st.caption(f"{s['ungraded']:,} attack rows are not graded yet and are left out.")

atk = sel[~sel["harmless"] & sel["attack_succeeded"].notna()].copy()
c1, c2 = st.columns(2)
with c1:
    st.markdown("**Caught vs missed, by attack family** (successful attacks only)")
    w = atk[atk["attack_succeeded"] == 1]
    fam = w.groupby("family")["caught"].agg(caught="sum", total="size").reset_index()
    fam["missed"] = fam["total"] - fam["caught"]
    long = fam.melt(id_vars=["family", "total"], value_vars=["caught", "missed"], var_name="outcome", value_name="n")
    bars = alt.Chart(long).mark_bar().encode(
        x=alt.X("n:Q", title="Successful attacks", stack="zero"),
        y=alt.Y("family:N", title=None, sort="-x"),
        color=alt.Color("outcome:N", title=None, scale=alt.Scale(domain=["caught", "missed"], range=[ui.GOOD, ui.BAD])),
        tooltip=["family", "outcome", "n"])
    st.altair_chart(ui.chart(bars, 60 * max(len(fam), 2)), width="stretch")
with c2:
    st.markdown("**Which layer fired** (all flagged attacks)")
    flagged = atk[atk["caught"]]
    det = pd.DataFrame([data.parse_detector(d) for d in flagged["detector"]])
    if det.empty:
        st.caption("Nothing flagged in this selection.")
    else:
        layer = det.apply(lambda r: "Both layers" if r.heuristic_fired and r.judge_fired else
                          "Pattern rules only" if r.heuristic_fired else "Judge model only" if r.judge_fired else "Other", axis=1)
        lc = layer.value_counts().rename_axis("layer").reset_index(name="n")
        donut = alt.Chart(lc).mark_arc(innerRadius=55).encode(
            theta="n:Q", color=alt.Color("layer:N", title=None,
                                         scale=alt.Scale(domain=["Pattern rules only", "Judge model only", "Both layers", "Other"],
                                                         range=[ui.ACCENT, ui.PURPLE, ui.GOOD, ui.MUTED])),
            tooltip=["layer", "n"])
        st.altair_chart(ui.chart(donut, 220), width="stretch")
        rules = det[det["heuristic_fired"]]["heuristic_rule"].value_counts()
        if len(rules):
            st.caption("Pattern rules that fired most: " + ", ".join(f"{k} ({v})" for k, v in rules.head(5).items()))

st.subheader("Successful attacks the detector missed")
st.caption("The analyst's review queue: these got a compliant reply and raised no alert. Open any id in the Alert explorer.")
miss = atk[(atk["attack_succeeded"] == 1) & ~atk["caught"]]
if miss.empty:
    st.caption("None in this selection.")
else:
    conn = data.connect()
    try:
        ids = tuple(int(i) for i in miss["id"].head(300))
        txt = pd.read_sql_query(f"SELECT id, substr(input, 1, 160) AS prompt, detector FROM alerts WHERE id IN ({','.join('?' * len(ids))})",
                                conn, params=ids)
    finally:
        conn.close()
    view = miss[["id", "run_id", "family", "probe_id"]].merge(txt, on="id")
    view["judge verdict"] = view["detector"].map(lambda d: data.parse_detector(d)["judge_label"] or "–")
    st.dataframe(view.drop(columns="detector").rename(columns={"id": "Alert", "run_id": "Round", "family": "Family", "probe_id": "Probe",
                                                               "prompt": "Prompt (start)", "judge verdict": "Judge verdict"}),
                 hide_index=True, width="stretch", height=320)
    if len(miss) > 300:
        st.caption(f"Showing 300 of {len(miss):,}.")

hl = sel[sel["harmless"] & sel["caught"]]
if len(hl):
    st.subheader("False alarms on harmless messages")
    conn = data.connect()
    try:
        ids = tuple(int(i) for i in hl["id"])
        fa = pd.read_sql_query(f"SELECT id, probe_id, substr(input, 1, 160) AS message, detector FROM alerts WHERE id IN ({','.join('?' * len(ids))})",
                               conn, params=ids)
    finally:
        conn.close()
    st.dataframe(fa.rename(columns={"id": "Alert", "probe_id": "Message type", "message": "Message (start)", "detector": "Detector"}),
                 hide_index=True, width="stretch")
