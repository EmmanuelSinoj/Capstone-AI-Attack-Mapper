#!/usr/bin/env python3
"""
Replays the benign customer-support set through the testbed's /chat endpoint so the detector's FALSE-ALARM rate can be
measured on live traffic (Emmanuel items 7/11; see detection/PLAN_run_probe_ids.md). Every request carries
probe_id "benign.<category>" and run_id "benign_<round token>", so it pairs with the attack runs of the same round.

The messages are MODEL-WRITTEN and only machine-screened; a human reviews the flagged rows plus a sample before any rate is
cited (detection/eval_judge/make_review_sheet.py). attack_succeeded stays NULL for benign rows.

Usage (stack up first: docker compose ps):
    python benign_replay_runner.py --limit 20            # quick trial / timing
    python benign_replay_runner.py                        # full set, today's current round
    python benign_replay_runner.py --round 20261006_v6-1  # same round as that day's Garak/PyRIT runs
Resumable: finished ids are kept in reports/<run_id>.progress.jsonl; rerun with the same --round and --resume.
Stdlib only (urllib + threads); concurrency 2 to match OLLAMA_NUM_PARALLEL=2.
"""
import argparse, json, pathlib, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import rounds

HERE = pathlib.Path(__file__).parent
SET_PATH = HERE.parent / "detection" / "eval_judge" / "benign_replay" / "benign_replay_set.json"
TESTBED_URL = "http://localhost:8000/chat"


def send(row: dict, run_id: str, version=None) -> dict:
    payload = {"prompt": row["text"], "probe_id": f"benign.{row['category']}", "run_id": run_id}
    if version is not None: payload["use_system_prompt_version"] = version
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(TESTBED_URL, data=body, headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=200) as r:
            ok = r.status == 200; r.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"id": row["id"], "ok": False, "error": str(e)[:120], "secs": round(time.time() - t0, 1)}
    return {"id": row["id"], "ok": ok, "secs": round(time.time() - t0, 1)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", default=None, help="Round token; default today's current round.")
    ap.add_argument("--new-round", action="store_true", help="Start a new round.")
    ap.add_argument("--limit", type=int, default=None, help="Only the first N messages (trial run).")
    ap.add_argument("--prompt-version", type=int, default=None, help="Run against this STORED system-prompt version (sent as use_system_prompt_version) instead of the active one. Needed for v1/v5 rounds on separate days.")
    ap.add_argument("--resume", action="store_true", help="Continue an interrupted run (same --round); skips finished ids.")
    a = ap.parse_args()
    rows = json.loads(SET_PATH.read_text(encoding="utf-8"))
    if a.limit: rows = rows[: a.limit]
    token = a.round or (rounds.new_round() if a.new_round else rounds.current_round())
    run_id = f"benign_{token}"
    prog = HERE / "reports" / f"{run_id}.progress.jsonl"; prog.parent.mkdir(exist_ok=True)
    if a.resume:
        done = {json.loads(l)["id"] for l in prog.read_text(encoding="utf-8").splitlines() if l.strip() and json.loads(l)["ok"]} if prog.exists() else set()
    else:
        rounds.claim_run_id("benign", token); done = set()
        prog.write_text("", encoding="utf-8")
    todo = [r for r in rows if r["id"] not in done]
    print(f"Round {token}  run_id {run_id}: {len(todo)} message(s) to send ({len(done)} already done)")
    fails = 0; t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as ex, open(prog, "a", encoding="utf-8") as pf:
        futs = [ex.submit(send, r, run_id, a.prompt_version) for r in todo]
        for n, f in enumerate(as_completed(futs), 1):
            res = f.result(); pf.write(json.dumps(res) + "\n"); pf.flush()
            if not res["ok"]: fails += 1
            if n % 25 == 0 or n == len(todo):
                el = time.time() - t0
                print(f"  {n}/{len(todo)} sent, {fails} failed, {el/60:.1f} min elapsed, ~{el/n*(len(todo)-n)/60:.0f} min left", flush=True)
    print(f"\nDone: {len(todo) - fails} ok, {fails} failed. Failed ids are in {prog}; rerun with --resume --round {token} to retry.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
