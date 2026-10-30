import altair as alt
import pandas as pd
import streamlit as st

import data
import ui

ABOUT = """
**What this page shows.** Whether the two-layer detector flagged the attacks, and how often it raised false alarms on normal
customer messages.

- **Layer 1, pattern rules** (heuristic rules on input and output, e.g. encoding smuggling, persona jailbreak, system-prompt leak).
- **Layer 2, judge model** (Prompt-Guard) labelling the input as JAILBREAK or INJECTION.
- An event counts as **caught** when the detector flagged it.

The key number is the share of **successful** attacks caught: those are the ones that matter. Failed attempts that were
flagged are reported separately. Rounds where the detector failed are left out.

**Reading the results.** The detection rate should be high and Critical: missed should be 0; the missed attacks are listed
for review. False alarms should stay near 0.

**Details** holds failed attempts that were flagged, ungraded rows, which layer fired and the top pattern rules.
"""

ui.header("Detection", "Two-layer detection: caught attacks, missed attacks and false alarms.", ABOUT, "Investigate")

mt = data.db_mtime()
df = data.live_rows(mt)
if df.empty:
    ui.no_data("No live data in the alert store yet.")
    st.stop()
df = data.window(df[df["kind"].isin(["garak", "pyrit", "benign"])])
rt = data.rounds_table(mt)
valid_rounds = [r for r in rt.index if not rt.loc[r, "invalid"] and r in set(df["run_id"])]
valid_sessions = sorted({rt.loc[r, "session"] for r in valid_rounds}, reverse=True)
opts = ["All valid rounds"] + [f"session:{x}" for x in valid_sessions] + valid_rounds
choice = st.selectbox("Rounds", opts, index=0,
                      format_func=lambda r: r if r == opts[0] else (f"Session {r[8:]} (Garak, PyRIT and harmless)" if r.startswith("session:")
                                                                    else f"Round {r} · {rt.loc[r, 'tool']} · prompt v{rt.loc[r, 'prompt_version']}"))
if choice == opts[0]:
    sel = df[~df["invalid_round"]]
elif choice.startswith("session:"):
    sel = df[(df["session"] == choice[8:]) & ~df["invalid_round"]]
else:
    sel = df[df["run_id"] == choice]
ui.scope(f"{sel['run_id'].nunique()} rounds", data.scope_versions(sel), data.scope_dates(), "rounds with a detector failure excluded")
s = data.detection_summary(sel)
missed = s["worked"] - s["worked_caught"]

ui.kpis([
    ("Detection rate", ui.pct(s["worked_caught"], s["worked"]), f"{s['worked_caught']:,} of {s['worked']:,} successful attacks", "good"),
    ("Critical: missed", f"{missed:,}", "worked and raised no alert", "bad" if missed else "good"),
    ("False alarms", ui.pct(s["harmless_flagged"], s["harmless"]) if s["harmless"] else "–",
     f"{s['harmless_flagged']} of {s['harmless']:,} harmless messages" if s["harmless"] else "no harmless messages here",
     "good" if not s["harmless_flagged"] else "warn"),
])
atk = sel[~sel["harmless"] & sel["attack_succeeded"].notna()].copy()
w = atk[atk["attack_succeeded"] == 1]
flagged = atk[atk["caught"]]
det = pd.DataFrame([data.parse_detector(d) for d in flagged["detector"]], index=flagged.index)

c1, c2 = st.columns([1, 1], gap="medium")
with c1:
    with ui.panel("Successful attacks: caught vs missed", "by family"):
        fam = w.groupby("family")["caught"].agg(caught="sum", total="size").reset_index()
        fam["missed"] = fam["total"] - fam["caught"]
        long = fam.melt(id_vars=["family", "total"], value_vars=["caught", "missed"], var_name="outcome", value_name="n")
        bars = alt.Chart(long).mark_bar().encode(
            x=alt.X("n:Q", title="Successful attacks", stack="zero"),
            y=alt.Y("family:N", title=None, sort="-x", axis=alt.Axis(labelOverlap=False)),
            color=alt.Color("outcome:N", title=None, scale=alt.Scale(domain=["caught", "missed"], range=[ui.GOOD, ui.SEV_COLOR["Critical"]])),
            tooltip=[alt.Tooltip("family:N", title="Family"), alt.Tooltip("outcome:N", title="Outcome"),
                     alt.Tooltip("n:Q", title="Successful attacks", format=",")])
        st.altair_chart(ui.chart(bars, 200), width="stretch")
with c2:
    with ui.panel("Detection rate", "successful attacks caught"):
        by = st.radio("Group by", ["Round", "Session"], horizontal=True, label_visibility="collapsed", key="det_rate_by")
        key = "run_id" if by == "Round" else "session"
        pr = w.groupby(key).agg(n=("id", "size"), c=("caught", "sum")).reset_index().rename(columns={key: "run_id"})
        pr["rate"] = pr["c"] / pr["n"]
        meta = (rt[["started", "prompt_version"]] if by == "Round" else
                rt.groupby("session").agg(started=("started", "min"), prompt_version=("prompt_version", lambda x: "/".join(sorted(set(x))))))
        pr = pr.merge(meta, left_on="run_id", right_index=True, how="left").sort_values("started")
        line = alt.Chart(pr).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2, color=ui.GOOD, size=46).encode(
            x=alt.X("run_id:N", title=None, sort=list(pr["run_id"]), axis=alt.Axis(labelAngle=0, labelLimit=200)),
            y=alt.Y("rate:Q", title="Caught", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
            tooltip=[alt.Tooltip("run_id:N", title=by), alt.Tooltip("prompt_version:N", title="Prompt"), alt.Tooltip("n:Q", title="Successful", format=","),
                     alt.Tooltip("c:Q", title="Caught", format=","), alt.Tooltip("rate:Q", title="Detection rate", format=".1%")])
        st.altair_chart(ui.chart(line, 200), width="stretch")

with ui.panel("Missed successful attacks", "analyst review queue"):
    miss = w[~w["caught"]]
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
        view = miss[["id", "ts", "severity", "run_id", "family", "probe_id"]].merge(txt, on="id")
        view["judge"] = view["detector"].map(lambda d: data.parse_detector(d)["judge_label"] or "–")
        view = pd.DataFrame({"Time (UTC)": view["ts"].dt.strftime("%d %b %H:%M:%S"), "Severity": view["severity"], "Alert": view["id"],
                             "Round": view["run_id"], "Family": view["family"], "Probe": view["probe_id"],
                             "Prompt (start)": view["prompt"], "Judge verdict": view["judge"]})
        st.dataframe(ui.sev_style(view), hide_index=True, width="stretch", height=300)
        st.caption(f"Showing {min(len(miss), 300):,} of {len(miss):,}. Open an alert ID in Alert explorer.")

hl = sel[sel["harmless"] & sel["caught"]]
if len(hl):
    with ui.panel("False alarms on harmless messages", f"{len(hl)} messages"):
        conn = data.connect()
        try:
            ids = tuple(int(i) for i in hl["id"])
            fa = pd.read_sql_query(f"SELECT id, probe_id, substr(input, 1, 160) AS message, detector FROM alerts WHERE id IN ({','.join('?' * len(ids))})",
                                   conn, params=ids)
        finally:
            conn.close()
        st.dataframe(fa.rename(columns={"id": "Alert", "probe_id": "Message type", "message": "Message (start)", "detector": "Detector"}),
                     hide_index=True, width="stretch")

with ui.details():
    ui.kpis([
        ("Failed attempts flagged", ui.pct(s["failed_caught"], s["failed"]), f"{s['failed_caught']:,} of {s['failed']:,}", None),
        ("Not graded", f"{s['ungraded']:,}", "attack rows left out", "warn" if s["ungraded"] else None),
    ])
    c1, c2 = st.columns([1, 1], gap="medium")
    with c1:
        with ui.panel("Which layer fired", "flagged attacks"):
            if det.empty:
                st.caption("Nothing flagged in this selection.")
            else:
                layer = det.apply(lambda r: "Both layers" if r.heuristic_fired and r.judge_fired else
                                  "Pattern rules only" if r.heuristic_fired else "Judge model only" if r.judge_fired else "Other", axis=1)
                lc = layer.value_counts().rename_axis("layer").reset_index(name="n")
                donut = alt.Chart(lc).mark_arc(innerRadius=42, outerRadius=72, stroke=ui.PANEL, strokeWidth=2).encode(
                    theta="n:Q", color=alt.Color("layer:N", title=None,
                                                 scale=alt.Scale(domain=["Pattern rules only", "Judge model only", "Both layers", "Other"],
                                                                 range=[ui.ACCENT, ui.PURPLE, ui.GOOD, ui.MUTED])),
                    tooltip=[alt.Tooltip("layer:N", title="Layer"), alt.Tooltip("n:Q", title="Flagged attacks", format=",")])
                st.altair_chart(ui.chart_legend(ui.chart(donut, 160), columns=1), width="stretch")
    with c2:
        with ui.panel("Top pattern rules", "flagged attacks"):
            rules = []
            for r in det.loc[det["heuristic_fired"], "heuristic_rule"] if not det.empty else []:
                rules += [x.strip() for x in r.split(",") if x.strip()]
            if rules:
                st.dataframe(pd.Series(rules).value_counts().head(8).rename_axis("Rule").reset_index(name="Events"),
                             hide_index=True, width="stretch")
            else:
                st.caption("No pattern rule fired in this selection.")
