#!/usr/bin/env python3
"""run_round.py -- run one full test ROUND: Garak + PyRIT + the benign replay, all under one round token, so the
attack runs and their benign false-alarm run are always paired (see detection/PLAN_run_probe_ids.md).

    python run_round.py                       # new round; Garak (promptinject,dan,encoding), PyRIT, benign replay
    python run_round.py --probes promptinject,dan --benign-limit 200
    python run_round.py --skip-garak          # e.g. PyRIT + benign only; the round still gets the benign run

Afterwards annotate Garak's rows (inside the container) -- the command is printed at the end.
A round with attack runs but no completed benign run is NOT valid for the false-alarm number: the benign run is never skipped."""
import argparse, pathlib, subprocess, sys
import rounds

HERE = pathlib.Path(__file__).parent


def step(name: str, cmd: list[str]) -> int:
    print(f"\n===== {name}: {' '.join(cmd)} =====", flush=True)
    return subprocess.run(cmd, cwd=HERE).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes", default=None, help="Garak probes (default: garak_runner.py's default).")
    ap.add_argument("--skip-garak", action="store_true")
    ap.add_argument("--skip-pyrit", action="store_true")
    ap.add_argument("--benign-limit", type=int, default=None, help="Only the first N benign messages (trial).")
    a = ap.parse_args()
    token = rounds.new_round()
    print(f"Round {token}")
    py = sys.executable; rc = {}
    if not a.skip_garak:
        rc["garak"] = step("Garak", [py, "garak_runner.py", "--round", token] + (["--probes", a.probes] if a.probes else []))
    if not a.skip_pyrit:
        rc["pyrit"] = step("PyRIT", [py, "pyrit_runner.py", "--round", token])
    rc["benign"] = step("Benign replay", [py, "benign_replay_runner.py", "--round", token] + (["--limit", str(a.benign_limit)] if a.benign_limit else []))
    print(f"\nRound {token} finished: " + ", ".join(f"{k}={'ok' if v == 0 else 'FAILED(%d)' % v}" for k, v in rc.items()))
    print("Next (PowerShell, from the project root):")
    print(f'  docker compose run --rm --no-deps -v "${{PWD}}/live_attack_path/attack_generation:/app/attack_generation:ro" testbed python3 /app/attack_generation/annotate_run.py {token} --dry-run')
    print("  (then the same command without --dry-run to write probe_id / attack_succeeded)")
    return 0 if all(v == 0 for v in rc.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
