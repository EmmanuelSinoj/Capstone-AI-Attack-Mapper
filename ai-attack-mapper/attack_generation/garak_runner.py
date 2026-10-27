#!/usr/bin/env python3
"""
Runs Garak's prompt-injection / jailbreak probes against the testbed's
/chat endpoint, using garak_config.json (a REST generator config -- see
that file's comments, and https://reference.garak.ai for the schema).

Garak's own detectors and report are NOT what feeds the Alert Store --
that's intentionally the job of this project's own detection layer
(live_attack_path/detection/), which the testbed calls on every /chat
request regardless of who's calling it. Garak's job here is purely to
be a diverse, well-tested source of attack payloads; its report is kept
on disk for reference (e.g. to sanity-check the detection layer's
recall against a known probe set) but the alerts our system reasons
over come from the testbed's own logging, not from parsing this report.

Usage:
    python garak_runner.py
    python garak_runner.py --probes promptinject,dan,encoding
    python garak_runner.py --probes promptinject --report-dir reports
    python garak_runner.py --no-fast   # stock garak settings, much slower

By default this loads garak_perf.yaml (fewer generations per prompt, a
lower soft prompt cap, and modest client-side parallelism matched to
Ollama's own concurrency limit) so a run finishes in a reasonable time
on a single local GPU instead of the multi-hour runtime garak's stock
settings produced on the first real attempt -- see that file's header
comment for the exact numbers and the garak docs they're based on. Use
--no-fast for a slower, more exhaustive run once these scripts are
being used for real numbers rather than iteration.

Before relying on this for real: garak's CLI flags have changed across
versions in the past. Run `garak --help` and `garak --list_probes` with
your installed version (`pip show garak`) to confirm `--model_type`,
`--generator_option_file`, and `--probes` are still the right flags --
this script assumes the schema documented at
https://reference.garak.ai/en/latest/garak.generators.rest.html as of
Sept 2026.
"""

import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys

import rounds

HERE = pathlib.Path(__file__).parent
CONFIG_PATH = HERE / "garak_config.json"
# Runtime-tuning config (fewer generations/prompts per probe, modest
# client-side parallelism matched to OLLAMA_NUM_PARALLEL in
# docker-compose.yml). See garak_perf.yaml's own header comment for the
# full rationale and the garak docs (faster.html, cliref.html,
# configurable.html) this was checked against -- added after the first
# real run (2026-09-18) was killed partway through, projected to take
# multiple hours at garak's stock settings. Loaded via --config
# alongside --generator_option_file; the two touch different config
# sections (system/run vs. plugins.generators) so there's no conflict.
PERF_CONFIG_PATH = HERE / "garak_perf.yaml"

# Garak uses the XDG Base Directory spec for its config/data/cache dirs,
# defaulting to ~/.config/garak, ~/.local/share/garak, ~/.cache/garak.
# On at least one team member's Windows machine, the real home folder
# (C:\Users\<name>\.config) refused directory creation with
# "PermissionError: [WinError 5] Access is denied" -- likely OneDrive
# folder redirection or an ACL quirk, not anything garak itself did
# wrong. Rather than debug every teammate's home-folder permissions,
# point these at a folder inside the project that's guaranteed
# writable. Set before garak is imported/run (it reads these at
# startup), and gitignored (see .gitignore) since it's local cache, not
# project state.
_GARAK_HOME = HERE / ".garak_home"
os.environ.setdefault("XDG_CONFIG_HOME", str(_GARAK_HOME / "config"))
os.environ.setdefault("XDG_DATA_HOME", str(_GARAK_HOME / "data"))
os.environ.setdefault("XDG_CACHE_HOME", str(_GARAK_HOME / "cache"))
for _p in (os.environ["XDG_CONFIG_HOME"], os.environ["XDG_DATA_HOME"], os.environ["XDG_CACHE_HOME"]):
    pathlib.Path(_p).mkdir(parents=True, exist_ok=True)

# A starting probe set scoped to this project's live-attack category
# (prompt injection / jailbreaking -- see Objectives, "Achievable and
# Relevant"). Expand as the Detection track needs more variety to test
# heuristics.py / judge.py against.
DEFAULT_PROBES = "promptinject,dan,encoding"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probes",
        default=DEFAULT_PROBES,
        help=f"Comma-separated garak probe names (default: {DEFAULT_PROBES})",
    )
    parser.add_argument(
        "--report-dir",
        default=str(HERE / "reports"),
        help="Directory to write garak's report files into (default: ./reports)",
    )
    parser.add_argument(
        "--no-fast",
        action="store_true",
        help=(
            "Skip garak_perf.yaml and run at garak's stock settings "
            "(5 generations/prompt, no cap, fully serial) -- much "
            "slower, but the more thorough option for a final/official "
            "run once the fast settings have been used to iterate."
        ),
    )
    parser.add_argument(
        "--round",
        default=None,
        help="Round token to run under (e.g. 20261006_v6-1). Default: today's current round (created if needed).",
    )
    parser.add_argument(
        "--new-round",
        action="store_true",
        help="Start a new round (use for a second Garak run on the same day).",
    )
    parser.add_argument("--prompt-version", type=int, default=None, help="Run against this STORED system-prompt version (sent as use_system_prompt_version) instead of the active one.")
    parser.add_argument("--seed", type=int, default=None, help="Garak random seed. Use the SAME seed and the same --probes for rounds that must be compared: the seed decides which prompts garak samples.")
    args = parser.parse_args()

    report_dir = pathlib.Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_prefix = str(report_dir / f"garak_run_{timestamp}")

    if not CONFIG_PATH.exists():
        print(f"ERROR: {CONFIG_PATH} not found.", file=sys.stderr)
        return 1

    # Round / run id: every request this run sends carries run_id in its body, so the testbed logs it on every alert row.
    round_token = args.round or (rounds.new_round() if args.new_round else rounds.current_round())
    run_id = rounds.claim_run_id("garak", round_token)
    gen_cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    gen_cfg["rest"]["RestGenerator"]["req_template_json_object"]["run_id"] = run_id
    if args.prompt_version is not None:
        gen_cfg["rest"]["RestGenerator"]["req_template_json_object"]["use_system_prompt_version"] = args.prompt_version
    run_config_path = report_dir / f"garak_run_{timestamp}.generator.json"
    run_config_path.write_text(json.dumps(gen_cfg, indent=2), encoding="utf-8")
    (report_dir / f"garak_run_{timestamp}.runinfo.json").write_text(
        json.dumps({"run_id": run_id, "round": round_token, "tool": "garak", "prompt_version": args.prompt_version, "seed": args.seed, "probes": args.probes, "started": timestamp,
                    "report_prefix": report_prefix}, indent=2), encoding="utf-8")
    print(f"Round {round_token}  run_id {run_id}")

    cmd = [
        "garak",
        "--model_type",
        "rest",
        "--generator_option_file",
        str(run_config_path),
        "--probes",
        args.probes,
        "--report_prefix",
        report_prefix,
    ]
    if args.seed is not None:
        cmd += ["--seed", str(args.seed)]

    if args.no_fast:
        print("Running at garak's STOCK settings (--no-fast): 5 generations/prompt,")
        print("no soft prompt cap, fully serial -- expect this to take hours.")
    elif PERF_CONFIG_PATH.exists():
        cmd += ["--config", str(PERF_CONFIG_PATH)]
        print(f"Using tuned settings from {PERF_CONFIG_PATH.name}: 2 generations/prompt,")
        print("soft_probe_prompt_cap=128, parallel_attempts=2 (matched to")
        print("OLLAMA_NUM_PARALLEL=2 in docker-compose.yml -- see that file's comment")
        print("before raising either number). Pass --no-fast for garak's slower,")
        print("more thorough stock behavior instead.")
    else:
        print(f"NOTE: {PERF_CONFIG_PATH} not found -- running at garak's stock")
        print("(slow) settings. See garak_perf.yaml's header comment if it's missing.")

    print("Make sure the stack is up first: docker compose ps  (ollama + testbed healthy)")
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        print(f"\nDone. Report written with prefix: {report_prefix}")
        print("Note: this report is garak's own scoring, kept for reference only --")
        print("the Alert Store already captured every interaction via the testbed's")
        print("own detection layer as it happened. Check alert_store/alerts.db.")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
