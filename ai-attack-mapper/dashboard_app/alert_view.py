"""Full view of one alert: request and reply, verdicts, Mapper classification and response.

Used by the Alert explorer and by the technique drill-down on the Classification page.
"""
from __future__ import annotations

import html
import json

import streamlit as st

import data
import ui


def technique_label(framework: str, raw_id: str) -> str:
    """'AML.T0051 · LLM Prompt Injection' when the reference tables know the ID, else the ID alone."""
    try:
        from mapper import framework_reference as fw
        r = fw.lookup(framework, raw_id)
        if r and r.resolved and r.name:
            name = r.name
            parent_id = raw_id.rsplit(".", 1)[0] if raw_id.count(".") >= (2 if raw_id.startswith("AML.") else 1) else None
            if parent_id:  # sub-technique: show it under its parent's name
                pr = fw.lookup(framework, parent_id)
                if pr and pr.resolved and pr.name and pr.name != name:
                    name = f"{pr.name}: {name}"
            return f"{raw_id} · {name}"
    except Exception:  # noqa: BLE001  reference tables not available
        pass
    return raw_id


def render(mt: float, alert_id: int, severity: str | None = None, run_id: str | None = None) -> None:
    """Full view of one alert. The Mapper result shown is the one from run_id (default: the sidebar's Mapper run)."""
    a = data.alert(mt, alert_id, run_id or data.selected_run())
    if a is None:
        st.warning(f"Alert {alert_id} not found.")
        return

    synthetic = a.get("source") == "synthetic"
    harmless = (a.get("probe_id") or "").startswith(data.HARMLESS)
    worked = a.get("attack_succeeded")
    caught = bool((a.get("category") or "").strip())
    d = data.parse_detector(a.get("detector"))
    if synthetic:
        tags = ["Synthetic alert", f"Answer key {a.get('ground_truth_category') or '–'}", a.get("source_reference") or ""]
        severity = None
    else:
        tags = [f"Round {a.get('run_id') or '–'}", f"Probe {a.get('probe_id') or '–'}", f"Prompt v{a.get('system_prompt_version') or '?'}"]
    tags = [t for t in tags if t]
    st.markdown(f"### Alert {alert_id}  " + (ui.badge(severity) + " " if severity else "")
                + "".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags), unsafe_allow_html=True)

    c1, c2 = st.columns([3, 2], gap="medium")
    with c1, ui.panel("Scenario and outcome" if synthetic else "Request and reply"):
        st.markdown("**Scenario**" if synthetic else "**Sent to the chatbot**")
        st.code(a.get("input") or "", language=None, wrap_lines=True)
        st.markdown("**Outcome**" if synthetic else "**Chatbot reply**")
        st.code(a.get("output") or "", language=None, wrap_lines=True)
    with c2, ui.panel("Verdicts"):
        mp0 = a.get("mapper")
        if synthetic:
            truth = a.get("ground_truth_category")
            pred = (mp0 or {}).get("predicted_category") if mp0 and mp0.get("valid_json") else None
            ui.callout(f"Synthetic alert written from a documented case; answer key: <b>category {html.escape(str(truth or '–'))}</b>",
                       "good")
            if pred is not None or (mp0 and mp0.get("valid_json")):
                ok = pred == truth
                ui.callout("Mapper " + ("<b>matches</b> the answer key" if ok else f"<b>does not match</b> (classified as {html.escape(str(pred or 'no attack'))})"),
                           "good" if ok else "bad")
        elif harmless:
            ui.callout("Harmless customer message: " + ("<b>flagged by the detector (false alarm)</b>" if caught else "not flagged (correct)"),
                       "bad" if caught else "good")
        else:
            ui.callout("Attack " + ("<b>worked</b>: the chatbot complied" if worked == 1 else "<b>failed</b>: the chatbot resisted" if worked == 0
                                    else "not graded yet"), "bad" if worked == 1 else "good")
            ui.callout("Detector: " + ("<b>caught</b>" if caught else "<b>missed</b>") +
                       f" · pattern rule: {d['heuristic_rule'] or 'none'} · judge model: {d['judge_label'] or '–'}",
                       "good" if caught else ("bad" if worked == 1 else "warn"))
        mp = a.get("mapper")
        st.markdown("**Mapper classification**")
        if not mp:
            st.caption("Not classified by the Mapper.")
        elif not mp.get("valid_json"):
            ui.callout(f"Classification failed: {html.escape(str(mp.get('error') or 'no valid reply'))}", "warn")
        else:
            cat = mp.get("predicted_category") or "No attack (out of scope)"
            conf = mp.get("confidence")
            sev = None
            try:
                from mapper.severity import severity_from_fields
                sev = severity_from_fields(mp.get("predicted_category"), mp.get("sub_cluster"), mp.get("adversarial"), conf,
                                           in_scope=bool(mp.get("in_scope"))).get("severity")
            except Exception:  # noqa: BLE001
                pass
            gate = mp.get("predicted_category") == "B" and conf is not None and conf >= data.GATE_THRESHOLD
            ui.kpis([("Category", cat, mp.get("sub_cluster") or "", "accent"),
                     ("Confidence", f"{conf:.2f}" if conf is not None else "–", "passes the hardening gate" if gate else "below the gate or not B",
                      "good" if gate else None),
                     ("Severity", sev or "–", mp.get("lifecycle_phase") or "", "bad" if sev in ("High", "Critical") else None)])
            try:
                from mapper import framework_reference as fw
            except ImportError:
                fw = None
            for label, key, col in (("ATLAS", "atlas", "atlas_technique"), ("OWASP LLM", "owasp_llm", "owasp_category"),
                                    ("ATT&CK", "attack", "attck_technique")):
                lst = data.ids(mp.get(col))
                if not lst:
                    continue
                parts = []
                for i in lst:
                    r = fw.lookup(key, i) if fw else None
                    name = f" {html.escape(r.name)}" if r and r.resolved and r.name else ""
                    parts.append(f'<a href="{r.url}" target="_blank">{html.escape(i)}</a>{name}' if r and r.url else html.escape(i) + name)
                st.markdown(f"<span class='muted'>{label}:</span> " + " · ".join(parts), unsafe_allow_html=True)
            if mp.get("rationale"):
                st.markdown(f'<div class="callout good" style="border-left-color:{ui.ACCENT}"><b>Rationale.</b> {html.escape(mp["rationale"])}</div>',
                            unsafe_allow_html=True)
            st.caption(f"Source: {mp.get('source')}")

    with ui.panel("Response"):
        pb = a.get("playbook")
        if pb:
            try:
                p = json.loads(pb)
            except ValueError:
                p = {"summary": pb}
            st.markdown(f"{html.escape(str(p.get('summary', '')))}")
            for i, stp in enumerate(p.get("containment_steps") or [], 1):
                st.markdown(f"{i}. {stp}")
            if p.get("recommended_control"):
                st.caption(f"Recommended control: {p['recommended_control']}")
        else:
            st.caption("No playbook for this alert yet.")
        st.caption("Hardening applied to this alert's attack: " + ("yes" if a.get("hardening_applied") else "no"))
