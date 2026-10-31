"""
mapper/pilot.py -- Model Selection Pilot harness on the 40 synthetic alerts, with a
fixed dev / held-out split (alert_store: assign_split.py --seed 42 --dev-fraction 0.4
-> 16 dev, 24 held-out, stratified by category).

Rules this harness enforces (from the team's evaluation plan):
  * The Mapper only ever sees db.get_mapper_input() -- id, source, input, output.
    The answer key is read only by the scoring code, never by the prompt.
  * Every run is stored with db.save_mapper_result() under its own run_id (one per
    model x prompt version x split x time), so nothing is overwritten and runs can be
    compared. Claude is not deterministic: use --repeats.
  * Iterate the prompt and compare models on DEV only. `run` defaults to dev.
  * Held-out runs ONCE, on a frozen model + prompt: `freeze` records the model and the
    exact prompt (version + text fingerprint) in evaluation/heldout_lock.json; a held-out
    run is refused unless the current prompt/model match the freeze, and refused a second
    time unless --rerun-reason is given (the reason is logged for the write-up).

Commands (run from ai-attack-mapper/):
  python -m mapper.pilot status
  python -m mapper.pilot run   --backend ollama --model llama3.2:latest            # dev
  python -m mapper.pilot run   --backend claude --repeats 3                        # dev, needs ANTHROPIC_API_KEY
  python -m mapper.pilot score                                                     # all runs, dev + held-out
  python -m mapper.pilot errors --run-id <id>                                      # dev error review
  python -m mapper.pilot freeze --backend claude --model claude-sonnet-5
  python -m mapper.pilot run   --backend claude --repeats 3 --split heldout        # once, after freeze

Live classification (frozen model + prompt only; results go to mapper_results as one run):
  python -m mapper.pilot --db <db> run --backend claude --model claude-haiku-5-5 --split live --ids-file gate_out.jsonl
  python -m mapper.pilot --db <db> run --backend claude --model claude-haiku-5-5 --split live --rounds garak_X,benign_X
  python -m mapper.pilot --db <db> run ... --resume <run_id>      # redo only failed alerts (e.g. after a network drop)
  python -m mapper.pilot --db <db> export-run --run-id <run_id> --out <path without extension>   # .db + .csv
  In Python: run(conn, "claude", split="live", model="claude-haiku-5-5", ids_file=..., rounds=[...]) -> run_id

Scoring (score / score_runs()):
  From the alert store's mapper_scores view: valid-JSON rate, category / sub-cluster /
  in-scope / adversarial accuracy. Category accuracy is reported two ways: over valid
  replies, and "strict" (an unusable reply counts as wrong).
  In Python: framework IDs three ways (agreed Oct 19) --
    primary : the model's FIRST ATLAS ID equals the key's atlas_technique_primary
    any     : any ID the model returned is in the key's list (ATLAS primary+supporting,
              ATT&CK, OWASP), per framework
    P/R/F1  : set precision / recall per framework
  and confidence calibration: mean confidence vs. accuracy (gap > 0 = overconfident),
  Brier score and a 5-bin expected calibration error, on category correctness.
  Small-sample caveat: dev has 4 alerts per category; one alert = 6.25% of dev accuracy.
"""

import argparse
import os
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from alert_store import db as alert_db

from . import classify, client, framework_reference as fw_ref, prompt, schema

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = REPO_ROOT / "evaluation" / "heldout_lock.json"
REPORT_DIR = REPO_ROOT / "evaluation"


# ----------------------------------------------------------------------------- helpers

def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.]+", "-", text).strip("-").lower()


def _model_name(backend: str, model: str | None) -> str:
    if model:
        return model
    if backend == "chat":
        raise SystemExit("--model is required for chat runs (the name used with import-chat).")
    return client.default_claude_model() if backend == "claude" else client.default_ollama_model()


def _split_ids(conn, split: str) -> list[int]:
    """Alert ids in one split. Reads only the split column of answer_key, never the labels."""
    return [r[0] for r in conn.execute(
        "SELECT alert_id FROM answer_key WHERE split = ? ORDER BY alert_id", (split,))]


def _load_lock() -> dict:
    if LOCK_PATH.exists():
        return json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    return {}


def _save_lock(lock: dict) -> None:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_text(json.dumps(lock, indent=2), encoding="utf-8")


def _norm(text) -> str:
    text = str(text or "").lower().replace("&", " and ")
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


# ----------------------------------------------------------------------------- running

def _read_ids_file(path: str) -> list[int]:
    """CSV/text: one alert id per line (a header like 'id' and blank lines are ignored).
    .jsonl (e.g. gate.py --out): one JSON object per line, alert id in 'rowid' (or 'alert_id'/'id')."""
    ids = []
    text = Path(path).read_text(encoding="utf-8-sig")
    if str(path).lower().endswith(".jsonl"):
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            key = next((k for k in ("rowid", "alert_id", "id") if k in obj), None)
            if key is None:
                raise SystemExit(f"{path} line {n}: no 'rowid', 'alert_id' or 'id' field.")
            ids.append(int(obj[key]))
    else:
        for line in text.splitlines():
            cell = line.split(",")[0].strip()
            if cell.isdigit():
                ids.append(int(cell))
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{path} lists some ids more than once.")
    return ids


def _check_frozen_model(backend: str, model_name: str) -> None:
    """Live testing must use a frozen model on the exact frozen prompt."""
    lock = _load_lock()
    frozen = [f for f in [lock.get("frozen")] + lock.get("secondary", []) if f]
    match = next((f for f in frozen if f["backend"] == backend and f["model"] == model_name), None)
    if match is None:
        raise SystemExit(f"Live run refused: {backend}/{model_name} is not a frozen model "
                         f"(frozen: {', '.join(f['backend'] + '/' + f['model'] for f in frozen) or 'none'}).")
    if match["prompt_fingerprint"] != prompt.prompt_fingerprint():
        raise SystemExit("Live run refused: the prompt changed since it was frozen "
                         f"({prompt.prompt_fingerprint()} != {match['prompt_fingerprint']}).")


def _round_ids(conn, rounds: list[str]) -> list[int]:
    """Alerts of the named rounds (alerts.run_id, exact match) that the Mapper queue would take:
    the intersection with db.get_mapper_queue(), so the selection rules stay the alert store's."""
    rounds = [r.strip() for r in rounds if r.strip()]
    if not rounds:
        raise SystemExit("--rounds is empty.")
    marks = ",".join("?" * len(rounds))
    counts = dict(conn.execute(f"SELECT run_id, COUNT(*) FROM alerts WHERE run_id IN ({marks}) GROUP BY run_id",
                               rounds).fetchall())
    unknown = [r for r in rounds if r not in counts]
    if unknown:
        raise SystemExit(f"No alerts with run_id {unknown} in this database (round names must match exactly).")
    queue = set(alert_db.get_mapper_queue(conn))
    picked = []
    for rnd in rounds:
        in_round = [r[0] for r in conn.execute("SELECT id FROM alerts WHERE run_id = ? ORDER BY id", (rnd,))]
        chosen = [i for i in in_round if i in queue]
        print(f"  round {rnd}: {len(chosen)} of {len(in_round)} alert(s) are in the Mapper queue")
        picked.extend(chosen)
    return picked


def _iter_attempts(todo, workers, backend, retries, kwargs):
    """Yield (alert, Attempt) in the order of `todo`. With workers > 1 the API calls run in
    parallel threads (they wait on the network, so this is a real speed-up); the caller still
    receives results one at a time, in order, so saving to the database, the printed lines and
    the stop-early checks work exactly as in the one-at-a-time run. Only the calling thread
    touches the database."""
    def one(alert):
        return classify.classify_alert_full(alert["id"], alert["source"], alert["input"], alert["output"],
                                            backend=backend, retries=retries, **kwargs)
    if workers <= 1:
        for alert in todo:
            yield alert, one(alert)
        return
    from concurrent.futures import ThreadPoolExecutor
    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        yield from zip(todo, ex.map(one, todo))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)   # on an early stop, do not start the rest


def run(conn, backend: str, split: str = "dev", model: str | None = None, repeats: int = 1,
        retries: int = 1, rerun_reason: str | None = None, resume: str | None = None,
        ids_file: str | None = None, rounds: list[str] | None = None, workers: int = 1,
        **backend_kwargs) -> str:
    """Classify every alert in `split`, `repeats` times, storing each reply. Returns the run_id.
    resume=<run_id>: continue an interrupted run -- same run_id, alerts that already have a
    valid reply are skipped, failed or missing ones are (re)done.
    split='live' + ids_file: classify exactly the listed alert ids (Live Classification Testing),
    with a frozen model and prompt only; held-out alerts are refused.
    split='live' + rounds: classify every alert of those rounds (alerts.run_id) that
    db.get_mapper_queue() would pick, as one run. ids_file and rounds can be combined."""
    model_name = _model_name(backend, model)
    if split == "heldout":
        _check_heldout_allowed(backend, model_name, rerun_reason)
    elif split == "live":
        if not ids_file and not rounds:
            raise SystemExit("--split live needs --ids-file and/or --rounds.")
        _check_frozen_model(backend, model_name)
    elif split != "dev":
        raise ValueError("split must be 'dev', 'heldout' or 'live'")

    if split == "live":
        ids = _read_ids_file(ids_file) if ids_file else []
        if rounds:
            seen = set(ids)
            ids += [i for i in _round_ids(conn, rounds) if i not in seen]
        heldout = set(_split_ids(conn, "heldout"))
        clash = sorted(set(ids) & heldout)
        if clash:
            raise SystemExit(f"Live run refused: {len(clash)} listed id(s) are held-out alerts: {clash[:10]}")
    else:
        ids = _split_ids(conn, split)
    if not ids:
        raise SystemExit(f"No '{split}' alerts. Load the answer key and run assign_split.py first.")
    alerts = alert_db.get_mapper_input(conn, ids=ids)   # id, source, input, output -- nothing else
    if split == "live":
        missing = sorted(set(ids) - {a["id"] for a in alerts})
        if missing:
            raise SystemExit(f"{len(missing)} listed id(s) are not in this database: {missing[:10]}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    run_id = f"pilot_{stamp}_{backend}_{_slug(model_name)}_{prompt.PROMPT_VERSION}_{split}"
    done = set()
    if resume:
        expected_tail = f"_{backend}_{_slug(model_name)}_{prompt.PROMPT_VERSION}_{split}"
        if not resume.endswith(expected_tail):
            raise SystemExit(f"Can't resume {resume}: it isn't a {backend}/{model_name} run on prompt "
                             f"{prompt.PROMPT_VERSION}, split {split}.")
        run_id = resume
        done = {(r[0], r[1]) for r in conn.execute(
            "SELECT alert_id, repeat_no FROM mapper_results WHERE run_id = ? AND valid_json = 1", (run_id,))}
        print(f"resuming {run_id}: {len(done)} valid repl(ies) already stored, skipping those")
    kwargs = dict(backend_kwargs)
    if model:
        kwargs["model"] = model

    print(f"run_id {run_id}: {len(alerts)} {split} alert(s) x {repeats} repeat(s), "
          f"prompt {prompt.PROMPT_VERSION} ({prompt.prompt_fingerprint()}), retries {retries}")
    backend_errors, successes, net_fails = [], 0, 0
    for rep in range(1, repeats + 1):
        todo = [a for a in alerts if (a["id"], rep) not in done]
        for alert, att in _iter_attempts(todo, workers, backend, retries, kwargs):
            note = att.error
            if att.ok:
                parts = []
                if att.attempts > 1:
                    parts.append(f"valid after {att.attempts} attempts")
                if att.meta.get("json_repaired"):
                    parts.append("json repaired (trailing comma)")
                if att.meta.get("ids_normalized"):
                    parts.append(f"ids normalized ({att.meta['ids_normalized']})")
                note = "; ".join(parts) or None
            alert_db.save_mapper_result(
                conn, alert["id"], run_id, model_name, att.parsed if att.ok else None,
                raw_output=att.raw_text, prompt_version=prompt.PROMPT_VERSION, repeat_no=rep, error=note,
                latency_ms=att.meta.get("latency_ms"), input_tokens=att.meta.get("input_tokens") or None,
                output_tokens=att.meta.get("output_tokens") or None,
            )
            status = f"{att.result.category} ({att.result.confidence})" if att.ok else f"FAIL {att.error[:80]}"
            warn = f"  [{att.meta['warning']}]" if att.meta.get("warning") else ""
            print(f"  rep {rep} alert {alert['id']:>3}: {status}{warn}")
            # Stop early if the backend rejects the first few requests the same way (bad key,
            # no credit, unsupported parameter...) instead of failing every alert.
            if not att.ok and (att.error or "").startswith("backend:"):
                backend_errors.append(att.error)
                if len(backend_errors) >= 3 and len(set(backend_errors)) == 1 and successes == 0:
                    raise SystemExit(f"\nStopped: the backend rejected 3 requests in a row with the same error:\n"
                                     f"  {att.error[:600]}\nFix that, then delete this run with: "
                                     f"py -m mapper.pilot delete-repeat --run-id {run_id} --repeat {rep}")
                # Network dropped mid-run (connection errors / timeouts, not content refusals):
                # stop instead of failing every remaining alert; --resume picks up from here.
                if "request failed" in att.error:
                    net_fails += 1
                    if net_fails >= 5:
                        raise SystemExit(f"\nStopped: 5 connection failures in a row ({att.error[:200]}).\n"
                                         f"Check your internet connection, then continue with the same command plus:\n"
                                         f"  --resume {run_id}")
                else:
                    net_fails = 0
            elif att.ok:
                successes += 1
                net_fails = 0

    if split == "heldout":
        lock = _load_lock()
        lock.setdefault("heldout_runs", []).append(
            {"run_id": run_id, "at": stamp, "rerun_reason": rerun_reason})
        _save_lock(lock)
    return run_id


def export_run(conn, run_id: str, out_base: str) -> tuple[Path, Path, int]:
    """Copy every mapper_results row of one run (all columns) into a new SQLite file
    (<out_base>.db, same table definition) and a CSV (<out_base>.csv), so the rows can be
    imported by alert_id into another database without sending the whole alerts.db."""
    import csv
    import sqlite3
    rows = conn.execute("SELECT * FROM mapper_results WHERE run_id = ? ORDER BY alert_id, repeat_no",
                        (run_id,)).fetchall()
    if not rows:
        raise SystemExit(f"No mapper_results rows for run {run_id}.")
    cols = [d[0] for d in conn.execute("SELECT * FROM mapper_results LIMIT 0").description]
    ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='mapper_results'").fetchone()[0]
    db_path, csv_path = Path(out_base + ".db"), Path(out_base + ".csv")
    for p in (db_path, csv_path):
        if p.exists():
            raise SystemExit(f"{p} already exists; choose another --out.")
    out = sqlite3.connect(db_path)
    try:
        out.execute(ddl)
        out.executemany(f"INSERT INTO mapper_results ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                        [tuple(r) for r in rows])
        out.commit()
        assert out.execute("SELECT COUNT(*) FROM mapper_results").fetchone()[0] == len(rows)
    finally:
        out.close()
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(tuple(r) for r in rows)
    return db_path, csv_path, len(rows)


def live_report(conn, run_id: str) -> dict:
    """No answer key for live alerts: report only what ran and what failed."""
    rows = [dict(r) for r in conn.execute(
        "SELECT alert_id, repeat_no, valid_json, predicted_category, confidence, error, raw_output "
        "FROM mapper_results WHERE run_id = ? ORDER BY alert_id, repeat_no", (run_id,))]
    failed = [{"alert_id": r["alert_id"], "repeat": r["repeat_no"], "error": r["error"],
               "raw_output_start": (r["raw_output"] or "")[:200]} for r in rows if not r["valid_json"]]
    notes = [{"alert_id": r["alert_id"], "repeat": r["repeat_no"], "note": r["error"]}
             for r in rows if r["valid_json"] and r["error"]]
    model = conn.execute("SELECT model FROM mapper_results WHERE run_id = ? LIMIT 1", (run_id,)).fetchone()
    return {"run_id": run_id, "model": model[0] if model else None, "prompt_version": prompt.PROMPT_VERSION,
            "prompt_fingerprint": prompt.prompt_fingerprint(), "replies": len(rows),
            "valid": sum(r["valid_json"] for r in rows), "failed_or_bad_json": failed,
            "valid_after_retry_or_repair": notes,
            "predicted_category_counts": dict(Counter(r["predicted_category"] for r in rows if r["valid_json"]))}


def freeze(backend: str, model: str | None, from_run: str | None = None,
           secondary_reason: str | None = None) -> dict:
    lock = _load_lock()
    if secondary_reason:
        # A second, separately reported held-out model (e.g. the cheaper production model).
        # The primary freeze is untouched; the prompt must be the same frozen prompt.
        primary = lock.get("frozen")
        if not primary:
            raise SystemExit("Freeze the primary model first; a secondary is only for a second report.")
        if primary["prompt_fingerprint"] != prompt.prompt_fingerprint():
            raise SystemExit("The prompt changed since the primary freeze; a secondary must use the same prompt.")
        name = _model_name(backend, model)
        sec = lock.setdefault("secondary", [])
        if any(s["backend"] == backend and s["model"] == name for s in sec) or \
                (primary["backend"] == backend and primary["model"] == name):
            raise SystemExit(f"{backend}/{name} is already frozen.")
        entry = {"backend": backend, "model": name, "prompt_version": prompt.PROMPT_VERSION,
                 "prompt_fingerprint": prompt.prompt_fingerprint(), "chosen_from_dev_run": from_run,
                 "reason": secondary_reason, "frozen_at": datetime.now(timezone.utc).isoformat()}
        sec.append(entry)
        _save_lock(lock)
        return entry
    if lock.get("frozen"):
        raise SystemExit(f"Already frozen: {lock['frozen']}. Edit {LOCK_PATH} by hand only if you mean it "
                         "(and say so in the write-up).")
    lock["frozen"] = {
        "backend": backend, "model": _model_name(backend, model),
        "prompt_version": prompt.PROMPT_VERSION, "prompt_fingerprint": prompt.prompt_fingerprint(),
        "chosen_from_dev_run": from_run, "frozen_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_lock(lock)
    return lock["frozen"]


def _check_heldout_allowed(backend: str, model_name: str, rerun_reason: str | None) -> None:
    frozen = _load_lock().get("frozen")
    if not frozen:
        raise SystemExit("Held-out is locked: choose the model and prompt on dev, then run "
                         "`python -m mapper.pilot freeze --backend ... --model ...` first.")
    problems = []
    secondaries = _load_lock().get("secondary", [])
    match = next((s for s in [frozen] + secondaries
                  if s["backend"] == backend and s["model"] == model_name), None)
    if match is None:
        allowed = ", ".join(f"{s['backend']}/{s['model']}" for s in [frozen] + secondaries)
        problems.append(f"model {backend}/{model_name} is not frozen (frozen: {allowed}); "
                        "add it with `freeze --secondary-reason \"...\"` to report it separately")
    elif match["prompt_fingerprint"] != prompt.prompt_fingerprint():
        problems.append("the prompt text changed since it was frozen")
    if problems:
        raise SystemExit("Held-out refused: " + "; ".join(problems))
    if _load_lock().get("heldout_runs") and not rerun_reason:
        raise SystemExit("Held-out has already been run once. Re-running needs --rerun-reason "
                         "(it is logged in evaluation/heldout_lock.json for the write-up).")


# ----------------------------------------------------------------------------- scoring

def _framework_truth(key_row) -> dict:
    """The key's IDs, canonicalized (revoked/retired IDs -> current replacement)."""
    raw_primary = (key_row["atlas_primary"] or "").strip()
    atlas_primary = fw_ref.canonical("atlas", raw_primary) if raw_primary else None
    atlas_all = ([atlas_primary] if atlas_primary else []) + _bare(fw_ref.parse_id_list(key_row["atlas_supporting"]), "atlas")
    return {"atlas_primary": atlas_primary, "atlas": set(atlas_all),
            "attack": set(_bare(fw_ref.parse_id_list(key_row["attck_techniques"]), "attack")),
            "owasp_llm": set(_bare(fw_ref.parse_id_list(key_row["owasp_categories"]), "owasp_llm"))}


def _bare(ids: list[str], framework: str) -> list[str]:
    """IDs reduced to bare, current IDs (strips appended names, maps revoked IDs), order kept."""
    return [fw_ref.canonical(framework, i) for i in ids]


def _ece(pairs: list[tuple[float, int]], bins=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0001)) -> float | None:
    if not pairs:
        return None
    total, err = len(pairs), 0.0
    for lo, hi in zip(bins, bins[1:]):
        b = [(c, y) for c, y in pairs if lo <= c < hi]
        if b:
            err += len(b) / total * abs(sum(c for c, _ in b) / len(b) - sum(y for _, y in b) / len(b))
    return round(err, 3)


def _mean(values) -> float | None:
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 3) if values else None


def score_runs(conn, run_id: str | None = None) -> list[dict]:
    """One summary dict per (run_id, split). Safe to call from the dashboard."""
    where, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    scores = [dict(r) for r in conn.execute(f"SELECT * FROM mapper_scores {where} ORDER BY run_id, alert_id", params)]
    if not scores:
        return []
    results = {r["id"]: dict(r) for r in conn.execute(
        f"SELECT id, alert_id, run_id, repeat_no, error, attck_technique, atlas_technique, owasp_category "
        f"FROM mapper_results {where}", params)}
    keys = {r["alert_id"]: r for r in conn.execute("SELECT * FROM answer_key")}
    fw_table = fw_ref._load()

    groups = defaultdict(list)
    for s in scores:
        groups[(s["run_id"], s["split"])].append(s)

    out = []
    for (rid, split), rows in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        n = len(rows)
        valid = [r for r in rows if r["valid_json"]]
        first_try = [r for r in valid if not (results[r["result_id"]]["error"] or "").startswith("valid after")
                     and "json repaired" not in (results[r["result_id"]]["error"] or "")]
        cat_flags = [r["category_correct"] for r in valid if r["category_correct"] is not None]

        # framework IDs
        fw = {f: {"p": [], "r": [], "any": []} for f in ("atlas", "attack", "owasp_llm")}
        primary_hits, unresolved, total_ids = [], 0, 0
        for r in valid:
            res, truth = results[r["result_id"]], _framework_truth(keys[r["alert_id"]])
            for f, col in (("atlas", "atlas_technique"), ("attack", "attck_technique"), ("owasp_llm", "owasp_category")):
                raw = fw_ref.parse_id_list(res[col])
                total_ids += len(raw)
                # strict: the string must be exactly a real ID (no appended name, no "00x" suffix)
                unresolved += sum(1 for i in raw if i.strip() not in fw_table[f])
                pred, gold = set(_bare(raw, f)), truth[f]
                if not gold:
                    continue  # nothing to compare against for this framework on this alert
                tp = len(pred & gold)
                fw[f]["r"].append(tp / len(gold))
                fw[f]["any"].append(1 if tp else 0)
                if pred:
                    fw[f]["p"].append(tp / len(pred))
                if f == "atlas" and truth["atlas_primary"]:
                    first = _bare(raw, "atlas")[:1]
                    primary_hits.append(1 if first and first[0] == truth["atlas_primary"] else 0)

        # sub-cluster: exact (the view) and normalized (case/punctuation-insensitive)
        sub_norm = [1 if _norm(r["predicted_sub_cluster"]) == _norm(r["truth_sub_cluster"]) else 0
                    for r in valid if r["truth_sub_cluster"] is not None and r["predicted_sub_cluster"] is not None]

        # calibration on category correctness
        pairs = [(r["confidence"], int(r["category_correct"])) for r in valid
                 if r["confidence"] is not None and r["category_correct"] is not None]
        mean_conf = _mean(c for c, _ in pairs)
        acc_conf = _mean(y for _, y in pairs)

        # repeat consistency: same category on every repeat of an alert
        by_alert = defaultdict(list)
        for r in rows:
            by_alert[r["alert_id"]].append(r["predicted_category"] if r["valid_json"] else "invalid")
        repeats = max(len(v) for v in by_alert.values())
        consistency = _mean(1 if len(set(v)) == 1 else 0 for v in by_alert.values()) if repeats > 1 else None

        confusion = Counter((r["truth_category"], r["predicted_category"] if r["valid_json"] else "invalid")
                            for r in rows)

        out.append({
            "run_id": rid, "split": split, "model": rows[0]["model"], "prompt_version": rows[0]["prompt_version"],
            "alerts": len(by_alert), "repeats": repeats, "replies": n,
            "valid_json_rate": round(len(valid) / n, 3),
            "first_try_valid_rate": round(len(first_try) / n, 3),
            "category_accuracy": _mean(cat_flags),
            "category_accuracy_strict": round(sum(cat_flags) / n, 3),
            "sub_cluster_accuracy_exact": _mean(r["sub_cluster_correct"] for r in valid),
            "sub_cluster_accuracy_normalized": _mean(sub_norm),
            "in_scope_accuracy": _mean(r["in_scope_correct"] for r in valid),
            "adversarial_accuracy": _mean(r["adversarial_correct"] for r in valid),
            "atlas_primary_match": _mean(primary_hits),
            **{f"{f}_any_match": _mean(v["any"]) for f, v in fw.items()},
            **{f"{f}_precision": _mean(v["p"]) for f, v in fw.items()},
            **{f"{f}_recall": _mean(v["r"]) for f, v in fw.items()},
            "malformed_id_rate": round(unresolved / total_ids, 3) if total_ids else None,
            "replies_needing_id_cleanup": _mean(1 if "ids normalized" in (results[r["result_id"]]["error"] or "") else 0
                                                for r in valid),
            "mean_confidence": mean_conf,
            "overconfidence_gap": round(mean_conf - acc_conf, 3) if mean_conf is not None else None,
            "brier": _mean((c - y) ** 2 for c, y in pairs),
            "ece_5bin": _ece(pairs),
            "repeat_consistency": consistency,
            "mean_latency_ms": _mean(r["latency_ms"] for r in rows),
            "confusion": {f"{t}->{p}": c for (t, p), c in sorted(confusion.items(), key=lambda kv: str(kv[0]))},
        })
    return out


def error_review(conn, run_id: str) -> list[dict]:
    """Dev error review: every wrong or unusable reply with what the key expected.
    Refuses held-out runs -- looking at held-out errors is how prompts get overfitted."""
    rows = [dict(r) for r in conn.execute(
        "SELECT s.*, m.rationale, m.raw_output, m.error, m.atlas_technique, m.attck_technique, m.owasp_category "
        "FROM mapper_scores s JOIN mapper_results m ON m.id = s.result_id WHERE s.run_id = ? ORDER BY s.alert_id",
        (run_id,))]
    if any(r["split"] == "heldout" for r in rows):
        raise SystemExit("Refusing to show held-out errors (only dev errors may inform prompt changes).")
    keys = {r["alert_id"]: r for r in conn.execute("SELECT * FROM answer_key")}
    out = []
    for r in rows:
        truth = _framework_truth(keys[r["alert_id"]])
        wrong = (not r["valid_json"]) or r["category_correct"] == 0
        out.append({**{k: r[k] for k in ("alert_id", "repeat_no", "truth_category", "predicted_category",
                                         "truth_sub_cluster", "predicted_sub_cluster", "confidence", "error")},
                    "wrong": wrong, "truth_atlas_primary": truth["atlas_primary"],
                    "predicted_atlas": fw_ref.parse_id_list(r["atlas_technique"]),
                    "rationale": r["rationale"], "raw_output": (r["raw_output"] or "")[:400]})
    return out


# ----------------------------------------------------------------------------- chat (manual) runs

CHAT_DIR = REPO_ROOT / "evaluation" / "chat_runs"

_CHAT_HEADER = (
    "You are acting as the classifier described below. Follow the instructions exactly and reply "
    "with ONLY the JSON object -- no other text.\n\n"
    "===== INSTRUCTIONS =====\n"
)


def export_chat(conn, split: str = "dev") -> Path:
    """Write one paste-ready prompt per alert (instructions + the alert exactly as the Mapper
    would send it) and an empty reply file next to it. Only db.get_mapper_input() is used,
    so nothing from the answer key can end up in a prompt. Held-out is refused while locked."""
    if split == "heldout":
        frozen = _load_lock().get("frozen")
        if not frozen or frozen["prompt_fingerprint"] != prompt.prompt_fingerprint():
            raise SystemExit("Held-out stays locked: freeze the model and this exact prompt first.")
    ids = _split_ids(conn, split)
    if not ids:
        raise SystemExit(f"No '{split}' alerts. Load the answer key and run assign_split.py first.")
    out = CHAT_DIR / f"{prompt.PROMPT_VERSION}_{split}"
    out.mkdir(parents=True, exist_ok=True)
    for alert in alert_db.get_mapper_input(conn, ids=ids):
        user = prompt.build_user_message(alert["id"], alert["source"], alert["input"], alert["output"])
        (out / f"alert_{alert['id']:03d}_prompt.txt").write_text(
            _CHAT_HEADER + prompt.SYSTEM_PROMPT + "\n===== ALERT TO CLASSIFY =====\n" + user + "\n",
            encoding="utf-8")
        reply = out / f"alert_{alert['id']:03d}_reply.txt"
        if not reply.exists():
            reply.write_text("", encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps({
        "prompt_version": prompt.PROMPT_VERSION, "prompt_fingerprint": prompt.prompt_fingerprint(),
        "split": split, "alert_ids": ids, "exported_at": datetime.now(timezone.utc).isoformat()}, indent=2),
        encoding="utf-8")
    return out


def _extract_json(text: str) -> tuple[dict, bool]:
    """A chat reply may wrap the JSON in prose or a code fence; take the outermost {...}.
    Returns (object, repaired) -- see client.loads_lenient."""
    try:
        return client.parse_json_response(text, report=True)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return client.loads_lenient(text[start:end + 1])


def import_chat(conn, model: str, folder: Path, run_id: str | None = None, repeat: int = 1) -> str:
    """Read the pasted replies in `folder` and store them as one run (run_id ..._chat_<model>_...).
    Each reply goes through the same JSON parsing, ID clean-up and schema validation as an API
    reply; an empty reply file is skipped, a reply that can't be used is stored as invalid."""
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest["prompt_fingerprint"] != prompt.prompt_fingerprint():
        raise SystemExit(f"These prompts were exported with prompt {manifest['prompt_version']} "
                         f"({manifest['prompt_fingerprint']}); the current prompt is {prompt.PROMPT_VERSION} "
                         f"({prompt.prompt_fingerprint()}). Export again and redo the chats.")
    split = manifest["split"]
    if split == "heldout":
        frozen = _load_lock().get("frozen") or {}
        if frozen.get("backend") != "chat" or frozen.get("model") != model:
            raise SystemExit(f"Held-out refused: frozen choice is {frozen.get('backend')}/{frozen.get('model')}, "
                             f"not chat/{model}.")
        if _load_lock().get("heldout_runs") and run_id is None:
            raise SystemExit("Held-out has already been imported once; add repeats with --run-id/--repeat.")
    if run_id is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        run_id = f"pilot_{stamp}_chat_{_slug(model)}_{prompt.PROMPT_VERSION}_{split}"
    # Guard: a repeat must come from fresh chats. If the reply files are word-for-word the
    # replies already stored under another repeat of this run, they were never replaced.
    if run_id is not None:
        previous = {}
        for r in conn.execute("SELECT alert_id, repeat_no, raw_output FROM mapper_results "
                              "WHERE run_id = ? AND repeat_no != ?", (run_id, repeat)):
            previous.setdefault(r["alert_id"], set()).add((r["raw_output"] or "").strip())
        files = {aid: (folder / f"alert_{aid:03d}_reply.txt") for aid in manifest["alert_ids"]}
        texts = {aid: f.read_text(encoding="utf-8").strip() for aid, f in files.items() if f.exists()}
        texts = {aid: t for aid, t in texts.items() if t}
        same = sum(1 for aid, t in texts.items() if t in previous.get(aid, set()))
        if texts and same == len(texts):
            raise SystemExit(f"All {same} reply files are identical to replies already stored for another repeat "
                             f"of {run_id}. Paste replies from NEW chats into the reply files first.")
        if same:
            print(f"warning: {same} reply file(s) are identical to an earlier repeat (unchanged files?)")
    stored = skipped = 0
    for aid in manifest["alert_ids"]:
        path = folder / f"alert_{aid:03d}_reply.txt"
        text = path.read_text(encoding="utf-8").strip() if path.exists() else ""
        if not text:
            skipped += 1
            continue
        parsed, error = None, None
        try:
            parsed, repaired = _extract_json(text)
            if not isinstance(parsed, dict):
                raise schema.SchemaValidationError("reply is not a JSON object")
            fixed = classify.normalize_framework_ids(parsed)
            schema.validate(parsed)
            notes = (["json repaired (trailing comma)"] if repaired else []) + \
                    ([f"ids normalized ({fixed})"] if fixed else [])
            error = "; ".join(notes) or None
        except (json.JSONDecodeError, schema.SchemaValidationError) as e:
            parsed, error = None, f"{type(e).__name__}: {e}"
        alert_db.save_mapper_result(conn, aid, run_id, model, parsed, raw_output=text,
                                    prompt_version=prompt.PROMPT_VERSION, repeat_no=repeat, error=error)
        stored += 1
        print(f"  alert {aid:>3}: {'ok ' + str(parsed.get('category')) if parsed else 'INVALID ' + error[:80]}")
    print(f"{run_id}: stored {stored} repl(ies), {skipped} empty reply file(s) skipped")
    if split == "heldout" and stored:
        lock = _load_lock()
        lock.setdefault("heldout_runs", []).append({"run_id": run_id, "at": run_id.split("_")[1],
                                                    "rerun_reason": "manual chat import"})
        _save_lock(lock)
    return run_id


def _clipboard():
    """(get, set) for the system clipboard. On Windows this goes through PowerShell's
    Get-/Set-Clipboard (via a UTF-8 temp file, so non-ASCII text survives); tkinter, the
    first version, exited silently on some Windows/Python setups. Elsewhere: tkinter."""
    import subprocess
    import sys
    import tempfile
    if sys.platform == "win32":
        def put(text: str) -> None:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
                f.write(text)
                tmp = f.name
            try:
                subprocess.run(["powershell", "-NoProfile", "-Command",
                                f"Get-Content -Raw -Encoding UTF8 -LiteralPath '{tmp}' | Set-Clipboard"],
                               check=True, capture_output=True)
            finally:
                os.unlink(tmp)

        def get() -> str:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"],
                                 check=True, capture_output=True)
            return out.stdout.decode("utf-8", errors="replace")

        return get, put
    import tkinter
    root = tkinter.Tk()
    root.withdraw()

    def get() -> str:
        try:
            return root.clipboard_get()
        except tkinter.TclError:
            return ""

    def put(text: str) -> None:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    return get, put


def _open_file(path: Path) -> None:
    """Open a prompt file in the default text editor (Notepad on Windows) for manual copying."""
    import subprocess
    import sys
    try:
        if sys.platform == "win32":
            subprocess.Popen(["notepad.exe", str(path)])
        else:
            print(f"    (open {path} yourself)")
    except Exception:  # noqa: BLE001
        print(f"    (open {path} yourself)")


def _drain_input() -> None:
    """Throw away any extra lines still waiting from a paste into the terminal (Windows)."""
    try:
        import msvcrt
        import time as _t
        _t.sleep(0.3)
        while msvcrt.kbhit():
            msvcrt.getwch()
    except ImportError:
        pass


def chat_assist(conn, split: str = "dev", clipboard=None, ask=input, manual: bool = False,
                redo: bool = False) -> Path:
    """Human-in-the-loop helper for a manual chat run. For each alert it puts the prompt on
    the clipboard, waits while you paste it into a NEW chat and copy the reply, then saves the
    clipboard into the reply file. It never talks to claude.ai itself -- that stays manual
    (scripted use of the chat app isn't allowed; use --backend claude for automation)."""
    folder = export_chat(conn, split)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    try:
        get, put = clipboard or _clipboard()
    except Exception as e:  # noqa: BLE001
        print(f"Clipboard not available ({e}); prompts will open in Notepad instead.")
        get, put, manual = (lambda: ""), (lambda t: None), True
    ids = manifest["alert_ids"]
    print(f"{len(ids)} alerts. For each: paste into a NEW chat outside the project, send, copy the WHOLE reply,"
          " then press Enter here.  s = skip this alert, q = stop (finished alerts stay saved).")
    done = 0
    prompts = {aid: (folder / f"alert_{aid:03d}_prompt.txt").read_text(encoding="utf-8").strip() for aid in ids}

    def looks_like_reply(text: str, aid: int) -> str | None:
        """None if `text` can be saved as alert `aid`'s reply, else the reason it can't."""
        if not text:
            return "the clipboard is empty"
        if "===== INSTRUCTIONS =====" in text or text in prompts.values():
            return "the clipboard holds a PROMPT, not Claude's reply"
        try:
            obj, _ = _extract_json(text)
            if isinstance(obj, dict) and str(obj.get("alert_id", aid)).strip() not in (str(aid), ""):
                return f"this reply is for alert {obj.get('alert_id')}, not alert {aid}"
        except json.JSONDecodeError:
            pass  # a refusal or broken JSON is allowed (asked about below) -- it's a real result
        return None

    for n, aid in enumerate(ids, 1):
        prompt_text = prompts[aid]
        reply_file = folder / f"alert_{aid:03d}_reply.txt"
        old_reply = reply_file.read_text(encoding="utf-8").strip() if reply_file.exists() else ""
        if old_reply and not redo and looks_like_reply(old_reply, aid) is None:
            print(f"[{n}/{len(ids)}] alert {aid}: already has a reply -- skipped (use --redo to replace)")
            continue
        prompt_path = folder / f"alert_{aid:03d}_prompt.txt"
        copied = False
        if not manual:
            try:
                put(prompt_text)
                copied = get().strip() == prompt_text
            except Exception:  # noqa: BLE001
                copied = False
        if copied:
            print(f"[{n}/{len(ids)}] alert {aid}: prompt is on your clipboard ({len(prompt_text)} characters).")
        else:
            print(f"[{n}/{len(ids)}] alert {aid}: opening {prompt_path.name} -- press Ctrl+A then Ctrl+C in it.")
            _open_file(prompt_path)
        cmd = ""
        while True:
            cmd = ask("    Paste it in a new chat, COPY the reply (don't paste it here), then press Enter "
                      "(s=skip, q=quit) > ").strip()
            if cmd.lower() in ("q", "s"):
                break
            if cmd:
                # Pasting the reply into this window feeds it in line by line; ignore all of it.
                print("    That looks like pasted text. Don't paste the reply here -- just copy it and press Enter.")
                _drain_input()
                continue
            reply = get().strip()
            problem = looks_like_reply(reply, aid)
            if problem:
                print(f"    Not saved: {problem}. Copy Claude's reply for alert {aid}, then press Enter.")
                continue
            if "{" not in reply:
                again = ask("    That doesn't look like JSON (maybe a refusal). Save it anyway? [y/N] > ")
                if again.strip().lower() != "y":
                    continue
            if old_reply and reply == old_reply:
                print("    Same text as the reply already saved for this alert -- is this from a new chat? Saved anyway.")
            reply_file.write_text(reply, encoding="utf-8")
            done += 1
            print(f"    saved ({len(reply)} characters)")
            break
        if cmd.lower() == "q":
            break
    print(f"\n{done} reply file(s) written in {folder}")
    return folder


# ----------------------------------------------------------------------------- CLI

_SHOW = ["split", "model", "prompt_version", "alerts", "repeats", "valid_json_rate", "first_try_valid_rate",
         "category_accuracy", "category_accuracy_strict", "sub_cluster_accuracy_normalized", "in_scope_accuracy",
         "adversarial_accuracy", "atlas_primary_match", "atlas_any_match", "attack_any_match", "owasp_llm_any_match",
         "atlas_precision", "atlas_recall", "malformed_id_rate", "replies_needing_id_cleanup", "mean_confidence", "overconfidence_gap",
         "brier", "ece_5bin", "repeat_consistency"]


def _print_scores(rows: list[dict]) -> None:
    for r in rows:
        print(f"\n== {r['run_id']} ==")
        for k in _SHOW:
            print(f"  {k:34s} {r.get(k)}")
        print(f"  {'confusion (truth->predicted)':34s} {r['confusion']}")
    if any(r["split"] == "dev" for r in rows):
        print("\nNote: dev has 4 alerts per category -- one alert moves dev accuracy by 6.25 points.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Model Selection Pilot (dev / held-out).")
    ap.add_argument("--db", default=None, help="alerts.db to use (default: alert_store/alerts.db)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run")
    p_run.add_argument("--backend", choices=["ollama", "claude"], required=True)
    p_run.add_argument("--model", default=None)
    p_run.add_argument("--host", default=None)
    p_run.add_argument("--split", choices=["dev", "heldout", "live"], default="dev")
    p_run.add_argument("--ids-file", default=None,
                       help="with --split live: CSV/text (one alert id per line) or gate .jsonl (rowid)")
    p_run.add_argument("--rounds", default=None,
                       help="with --split live: comma-separated round names (alerts.run_id); every alert "
                            "of those rounds that get_mapper_queue() would pick, as one run")
    p_run.add_argument("--repeats", type=int, default=1)
    p_run.add_argument("--retries", type=int, default=1, help="re-asks after an unusable reply (default 1)")
    p_run.add_argument("--workers", type=int, default=1,
                       help="API calls in flight at once (default 1 = one at a time; 4-6 is about 4-6x faster)")
    p_run.add_argument("--rerun-reason", default=None)
    p_run.add_argument("--resume", default=None, metavar="RUN_ID", help="continue an interrupted run")

    p_score = sub.add_parser("score")
    p_score.add_argument("--run-id", default=None)
    p_score.add_argument("--out", default=None)

    p_err = sub.add_parser("errors")
    p_err.add_argument("--run-id", default=None, help="default: the most recent dev run")
    p_err.add_argument("--all", action="store_true", help="show correct replies too")

    p_freeze = sub.add_parser("freeze")
    p_freeze.add_argument("--backend", choices=["ollama", "claude", "chat"], required=True,
                          help="'chat' = replies pasted from the Claude chat app (import-chat)")
    p_freeze.add_argument("--model", default=None)
    p_freeze.add_argument("--from-run", default=None, help="the dev run_id this choice was based on")
    p_freeze.add_argument("--secondary-reason", default=None,
                          help="freeze an extra model, reported separately; the primary freeze is kept")

    p_exp = sub.add_parser("export-chat", help="write paste-ready prompts for a manual chat run")
    p_exp.add_argument("--split", choices=["dev", "heldout"], default="dev")

    p_ast = sub.add_parser("chat-assist", help="clipboard helper: copies each prompt, saves each reply")
    p_ast.add_argument("--split", choices=["dev", "heldout"], default="dev")
    p_ast.add_argument("--redo", action="store_true", help="replace replies that already exist")
    p_ast.add_argument("--notepad", action="store_true",
                       help="open each prompt in Notepad instead of using the clipboard for it")

    p_imp = sub.add_parser("import-chat", help="store the replies pasted from a chat as a run")
    p_imp.add_argument("--model", required=True, help="e.g. claude-chat-sonnet-5.5")
    p_imp.add_argument("--split", choices=["dev", "heldout"], default="dev")
    p_imp.add_argument("--dir", default=None, help="default: evaluation/chat_runs/<prompt version>_<split>")
    p_imp.add_argument("--run-id", default=None, help="add to an existing chat run (with --repeat)")
    p_imp.add_argument("--repeat", type=int, default=1)

    p_del = sub.add_parser("delete-repeat", help="remove one repeat of a dev run (e.g. a mistaken import)")
    p_del.add_argument("--run-id", required=True)
    p_del.add_argument("--repeat", type=int, required=True)

    p_xp = sub.add_parser("export-run", help="write one run's mapper_results rows to a new .db and .csv")
    p_xp.add_argument("--run-id", required=True)
    p_xp.add_argument("--out", required=True, help="output path without extension, e.g. evaluation/mapper_results_X")

    sub.add_parser("status")
    a = ap.parse_args(argv)

    conn = alert_db.get_connection(a.db)
    try:
        if a.cmd == "run":
            kwargs = {"host": a.host} if (a.host and a.backend == "ollama") else {}
            rid = run(conn, a.backend, split=a.split, model=a.model, repeats=a.repeats, retries=a.retries,
                      rerun_reason=a.rerun_reason, resume=a.resume, ids_file=a.ids_file,
                      rounds=a.rounds.split(",") if a.rounds else None, workers=a.workers, **kwargs)
            if a.split == "live":
                rep = live_report(conn, rid)
                REPORT_DIR.mkdir(parents=True, exist_ok=True)
                out = REPORT_DIR / f"{rid}_report.json"
                out.write_text(json.dumps(rep, indent=2), encoding="utf-8")
                print(f"\n== {rid} ==\n  model {rep['model']}, prompt {rep['prompt_version']} "
                      f"({rep['prompt_fingerprint']})\n  valid {rep['valid']}/{rep['replies']}, "
                      f"failed or bad JSON: {len(rep['failed_or_bad_json'])}, "
                      f"valid only after retry/repair: {len(rep['valid_after_retry_or_repair'])}\n"
                      f"  predicted categories: {rep['predicted_category_counts']}\n  report: {out}")
                for f in rep["failed_or_bad_json"]:
                    print(f"  FAILED alert {f['alert_id']}: {(f['error'] or '')[:150]}")
                # Last line on purpose: the orchestrator takes the LAST pilot_... match in the
                # output as the run id (the report path above also contains one).
                print(f"MAPPER_RUN_ID {rid}")
            else:
                _print_scores(score_runs(conn, rid))
        elif a.cmd == "score":
            rows = score_runs(conn, a.run_id)
            if not rows:
                print("No scored runs yet.")
                return 1
            _print_scores(rows)
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            out = Path(a.out) if a.out else REPORT_DIR / f"pilot_scores_{time.strftime('%Y%m%dT%H%M%S')}.json"
            out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
            print(f"\nWritten to {out}")
        elif a.cmd == "errors":
            rid = a.run_id or next((r[0] for r in conn.execute(
                "SELECT run_id FROM mapper_results WHERE run_id LIKE '%\\_dev' ESCAPE '\\' "
                "ORDER BY created_at DESC LIMIT 1")), None)
            if not rid:
                print("No dev runs yet.")
                return 1
            print(f"Errors for {rid}:")
            for e in error_review(conn, rid):
                if e["wrong"] or a.all:
                    print(json.dumps(e, indent=2, ensure_ascii=False))
        elif a.cmd == "freeze":
            print("Frozen:", json.dumps(freeze(a.backend, a.model, a.from_run, a.secondary_reason), indent=2))
        elif a.cmd == "export-chat":
            out = export_chat(conn, a.split)
            print(f"Prompts written to {out}")
            print("For each alert_NNN_prompt.txt: open a NEW chat (not in the capstone project), paste the whole file,")
            print("then paste Claude's full reply into alert_NNN_reply.txt and save.")
        elif a.cmd == "chat-assist":
            chat_assist(conn, a.split, manual=a.notepad, redo=a.redo)
            print("Next: py -m mapper.pilot import-chat --model <name> [--run-id <id> --repeat N]"
                  + (" --split heldout" if a.split == "heldout" else ""))
        elif a.cmd == "import-chat":
            folder = Path(a.dir) if a.dir else CHAT_DIR / f"{prompt.PROMPT_VERSION}_{a.split}"
            rid = import_chat(conn, a.model, folder, run_id=a.run_id, repeat=a.repeat)
            _print_scores(score_runs(conn, rid))
        elif a.cmd == "delete-repeat":
            if not a.run_id.endswith("_dev"):
                print("Only dev runs can be edited; held-out results stay as recorded.")
                return 1
            n = conn.execute("DELETE FROM mapper_results WHERE run_id = ? AND repeat_no = ?",
                             (a.run_id, a.repeat)).rowcount
            conn.commit()
            print(f"deleted {n} row(s): {a.run_id} repeat {a.repeat}")
        elif a.cmd == "export-run":
            db_path, csv_path, n = export_run(conn, a.run_id, a.out)
            print(f"{n} row(s) of {a.run_id} written to:\n  {db_path}\n  {csv_path}")
        elif a.cmd == "status":
            splits = dict(conn.execute("SELECT COALESCE(split, 'unassigned'), COUNT(*) FROM answer_key GROUP BY 1").fetchall())
            print("answer_key rows by split:", splits or "none -- load the answer key first")
            print("prompt:", prompt.PROMPT_VERSION, prompt.prompt_fingerprint())
            print("runs:", [r[0] for r in conn.execute("SELECT DISTINCT run_id FROM mapper_results ORDER BY run_id")])
            print("held-out lock:", json.dumps(_load_lock(), indent=2) if LOCK_PATH.exists() else "none (held-out locked)")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
