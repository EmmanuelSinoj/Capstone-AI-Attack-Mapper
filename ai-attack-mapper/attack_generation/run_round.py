#!/usr/bin/env python3
"""run_round.py -- run one full test ROUND: Garak + PyRIT + the benign replay, all under one round token, so the
attack runs and their benign false-alarm run are always paired (see detection/PLAN_run_probe_ids.md).

    python run_round.py                       # new round; Garak (promptinject,dan,encoding), PyRIT, benign replay
    python run_round.py --probes promptinject,dan --benign-limit 200
    python run_round.py --skip-garak          # e.g. PyRIT + benign only; the round still gets the benign run

JUDGE GUARD (added 2026-10-05 after round 20261005_v6-2 was logged with a dead judge): before the round starts the testbed's
judge must pass a health check (GET /judge/health: no failures so far, and a canary pair -- a known attack prompt scoring
>= 9.1 and a known benign prompt scoring <= -5). While the round runs, a watcher polls the same endpoint every 20 s; the canary
re-runs after every 250 judge calls. If the judge stops scoring correctly, the running step is killed, the round is marked
INVALID in reports/rounds.json, and this script exits with code 3. Needs the testbed running with the fault-fix app.py/judge.py.

Afterwards annotate Garak's rows (inside the container) -- the command is printed at the end.
A round with attack runs but no completed benign run is NOT valid for the false-alarm number: the benign run is never skipped."""
import argparse, os, pathlib, subprocess, sys
import judge_guard, rounds

HERE = pathlib.Path(__file__).parent


def _kill(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    else:
        proc.terminate()


def step(name: str, cmd: list[str], watcher: judge_guard.Watcher) -> int:
    print(f"\n===== {name}: {' '.join(cmd)} =====", flush=True)
    proc = subprocess.Popen(cmd, cwd=HERE)
    watcher.on_trip = lambda: _kill(proc)
    rc = proc.wait()
    return 3 if watcher.tripped else rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes", default=None, help="Garak probes (default: garak_runner.py's default).")
    ap.add_argument("--skip-garak", action="store_true")
    ap.add_argument("--skip-pyrit", action="store_true")
    ap.add_argument("--benign-limit", type=int, default=None, help="Only the first N benign messages (trial).")
    ap.add_argument("--prompt-version", type=int, default=None, help="Run the WHOLE round (Garak, PyRIT, benign) against this stored system-prompt version, without activating it.")
    ap.add_argument("--base", default=judge_guard.BASE, help="Testbed base URL (default %(default)s).")
    a = ap.parse_args()
    try:
        h = judge_guard.preflight(a.base)
    except judge_guard.JudgeProblem as e:
        print(f"ABORT before starting a round: {e}"); return 3
    print("Judge pre-flight OK:", judge_guard.describe(h))
    token = rounds.new_round()
    print(f"Round {token}")
    watcher = judge_guard.Watcher(a.base); watcher.start()
    py = sys.executable; rc = {}
    pv = ["--prompt-version", str(a.prompt_version)] if a.prompt_version is not None else []
    try:
        if not a.skip_garak:
            rc["garak"] = step("Garak", [py, "garak_runner.py", "--round", token] + pv + (["--probes", a.probes] if a.probes else []), watcher)
        if not a.skip_pyrit and not watcher.tripped:
            rc["pyrit"] = step("PyRIT", [py, "pyrit_runner.py", "--round", token] + pv, watcher)
        if not watcher.tripped:
            rc["benign"] = step("Benign replay", [py, "benign_replay_runner.py", "--round", token] + pv + (["--limit", str(a.benign_limit)] if a.benign_limit else []), watcher)
    finally:
        watcher.stop()
    try:    # final check: the judge must also be fine at the end (counters cover the whole round)
        fh = judge_guard.fetch(a.base, force=True)
        if not fh.get("ok") and not watcher.tripped: watcher.tripped = "final judge check failed: " + judge_guard.describe(fh)
        print("Judge at end of round:", judge_guard.describe(fh))
    except Exception as e:  # noqa: BLE001
        if not watcher.tripped: watcher.tripped = f"final judge check unreachable ({e!r})"
    if watcher.tripped:
        rounds.mark_invalid(token, "judge guard: " + watcher.tripped)
        print(f"\nRound {token} is INVALID (marked in reports/rounds.json): {watcher.tripped}")
        print("Do NOT quote its flag rates. Fix the judge (docker compose restart testbed; run judge_concurrency_check.py), then start a new round.")
        print("Attack-success grades (annotate_run.py) are still valid for the rows that were logged.")
        return 3
    print(f"\nRound {token} finished: " + ", ".join(f"{k}={'ok' if v == 0 else 'FAILED(%d)' % v}" for k, v in rc.items()) + "  (judge guard: no problem seen)")
    print("Next (PowerShell, from the project root):")
    print(f'  docker compose run --rm --no-deps -v "${{PWD}}/live_attack_path/attack_generation:/app/attack_generation:ro" testbed python3 /app/attack_generation/annotate_run.py {token} --dry-run')
    print("  (then the same command without --dry-run to write probe_id / attack_succeeded)")
    return 0 if all(v == 0 for v in rc.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
