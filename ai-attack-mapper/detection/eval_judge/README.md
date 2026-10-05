# eval_judge: evaluation scripts, saved scores, results

Paths below are relative to `ai-attack-mapper/detection/eval_judge/` in the repo. Scripts find their data next to themselves, so every data file listed here goes **directly in this folder**.

## Data files the scripts need (not all are in git)

In git: `labeled_prompts_500.json`, `stress_prompts.json`, `support_benign_210.json` (ours, model-written) and the saved score files. **Not in git, place them in this folder yourself:** `jailbreakhub_1000_train.json`, `jailbreakhub_1000_test.json`, `heuristics_v5_train_scores.jsonl` and `heur_v5/` (Emmanuel's JailbreakHub split and v5 code).

| File | Used by | Where it comes from |
|---|---|---|
| `jailbreakhub_1000_train.json` (700 prompts, 350 attack / 350 normal, SHA256 starts `03bf746316fa5aa3`) | judge_calibrate, judge_kfold_validate, combined_train_cv, compare_fuzzy_off, encoding_rule_eval | Emmanuel's JailbreakHub split |
| `jailbreakhub_1000_test.json` (300 prompts, 150/150, SHA256 starts `28e19cc2b9cda6ad`) | judge_test_validate | same split. **Locked**: do not use it to choose thresholds or rules |
| `labeled_prompts_500.json` | judge_score_short, exact_score_short, short_analysis, short_full_report, encoding_rule_eval | short labeled prompts (model-written) |
| `stress_prompts.json` | same as above | 30 attack / 40 normal stress prompts |
| `support_benign_210.json` | judge_score_support, support_analysis, encoding_rule_eval | 210 ordinary support messages, built by `build_support_benign.py`. Model-written, **pending human review** |
| `heuristics_v5_train_scores.jsonl` | combined_train_cv, compare_fuzzy_off | Emmanuel's v5 per-prompt results on the 700 (patterns + fuzzy) |
| `heur_v5/` | compare_fuzzy_off | Emmanuel's v5 detection code, kept untouched for the comparison |
| `encoding_holdout_80.json` (in git, frozen, SHA256 starts `99353c14bf439611`) | encoding_rule_eval | 41 encoding attacks + 40 hard negatives written independently of the patterns |

Saved scores (`judge_*_scores*.jsonl`, `exact_short_scores.jsonl`) are what the host-side scripts read; regenerate them only with the container-side scripts below.

`encoding_rule_eval.py` also reads the Garak report files in `ai-attack-mapper/attack_generation/reports/` (`*.report.jsonl`, `*.hitlog.jsonl`). The Garak encoding numbers it prints are **in-sample**: the encoding patterns were written after looking at those probes. Only the holdout numbers are independent (see the caveat at the top of `encoding_rule_eval_output.txt`).

## Where each script runs

Inside the testbed container (needs the GPU, the model and `HF_TOKEN`), e.g. `docker compose exec testbed python3 /app/detection/eval_judge/<script>`:
`judge_calibrate.py`, `judge_score_short.py`, `judge_score_support.py`, `verify_live_detection.py` (expects PASS), `../reporting/rescore_judge.py`, and `judge_test_validate.py` (already run once on the locked 300; do not re-run it to select anything).

On the host (plain Python, read the saved scores): `judge_kfold_validate.py`, `combined_train_cv.py`, `exact_score_short.py`, `short_analysis.py`, `short_full_report.py`, `support_analysis.py`, `compare_fuzzy_off.py` (slow: runs the v5 fuzzy matcher, a few minutes), `locked_300_combined.py`, `dan_overlap.py` (how many Garak dan.DanInTheWild prompts are also in our JailbreakHub files), `encoding_rule_eval.py`, `build_support_benign.py`, `build_label_audit.py`.

## Benign replay set (false-alarm measurement)

`benign_replay/` holds 1,380 benign customer-support messages in 14 categories (model-written, machine-screened only; 1,170 new + the 210 in `support_benign_210.json`, exact duplicates removed). Steps: `build_benign_replay_set.py` (host) -> `score_benign_replay.py` (container, judge scores) -> `make_review_sheet.py` (host) writes `benign_review_sheet.csv` with every v6-flagged message plus a random 100 unflagged. Two humans fill `human_label` (benign / attack / unclear) independently; `make_review_sheet.py --summarize <sheet>` then prints the false-alarm rate with 95% CI per category. The set is replayed LIVE through `/chat` under a `benign_<round>` run id (see `../PLAN_run_probe_ids.md`).

## Results kept in the repo

- `chosen_thresholds.json`: the earlier "at most 10% normal flagged" rule (judge alone, 9.5). v6 uses 9.1; see `../VERSION.md`.
- `compare_fuzzy_off_output.txt`: v5 versus v6 on the training set, with the fuzzy matcher off.
- `locked_300_combined_output.txt`: patterns OR judge on the locked 300 from saved scores (100/150 caught, 41/150 flagged at 9.1). Fixed thresholds, nothing tuned on it.
- `encoding_rule_eval_output.txt`: effect of the 5 encoding patterns (holdout is independent, Garak is in-sample).
