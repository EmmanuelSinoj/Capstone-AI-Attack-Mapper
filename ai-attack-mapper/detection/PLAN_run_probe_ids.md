# Plan: probe_id, run_id and attack_succeeded on every live row (Emmanuel items 7, 10, part of 8)

Status: plan only, written 2026-10-04 for Mon Oct 5. Nothing below is built yet. Emmanuel's date is Oct 10; live classification testing starts Oct 6, so the code lands before the first live run.

## What exists today
- `alerts` already has `probe_id`, `run_id` and `attack_succeeded` columns (`schema.sql`).
- `/chat` accepts an optional `probe_id` and passes it to `logger.py`. **`run_id` and `attack_succeeded` are never passed**, so they are NULL on every live row.
- Garak talks to `/chat` through its REST generator, which sends only the prompt. Garak's own files hold the probe name and the success result: `*.report.jsonl` (every attempt, with `probe_classname`) and `*.hitlog.jsonl` (the attempts that worked).
- PyRIT (`pyrit_runner.py`) has no scorer, so its outcomes are "undetermined". It now saves `reports/pyrit_run_<UTC>.json` (objective, outcome, response).

## run_id
- Format `<tool>_<YYYYMMDD>_<DETECTION_VERSION>`, e.g. `garak_20261006_v6-1`, `pyrit_20261006_v6-1`, `benign_20261008_v6-1`. Every run also gets a same-day counter starting at 1: `garak_20261006_v6-1`, then `-2`, `-3` for later runs that day (decided 2026-10-04). The version comes from `detection.DETECTION_VERSION` so it cannot drift.
- Set once at the start of each run by the runner and sent with every request: `/chat` gets an optional `run_id` field and `logger.py` writes it. For Garak the runner writes it into the REST generator's request body template; for PyRIT it is part of the target request.

## probe_id
- **Garak:** the probe class name, e.g. `promptinject.HijackHateHumans`, `dan.Dan_11_0`, `encoding.InjectNato`. Garak does not send it live, so a script `annotate_run.py <run_id>` fills it after the run by matching each row's prompt text (exactly) to the attempts in the run's `report.jsonl`. Rows with no match are listed, not guessed.
- **PyRIT:** `pyrit.<attack>.<objective id>`, sent live by `pyrit_runner.py` (we control the caller).
- **Benign replay:** `benign.<set name>`, e.g. `benign.support_210`.

## attack_succeeded (1 / 0 / NULL)
- **Garak:** from Garak's own grading, in the same `annotate_run.py` pass: 1 if the attempt is in `hitlog.jsonl`, 0 if it was graded and not a hit. Done after the run, never during, so it cannot affect detection.
- **PyRIT:** add a PyRIT true/false scorer using the local model and write 1/0 from it (decided 2026-10-04: we make a scorer). The scorer's verdicts are model judgements, so the report says PyRIT success is model-graded.
- **Benign traffic:** NULL (not an attack). The report treats a row as benign by its `run_id`/`probe_id`.
- The detector's verdict stays in `category`/`detector`; `attack_succeeded` is only the tool's judgement of whether the attack worked. Nobody edits it by hand.

## Check before the first live run (Oct 6)
After one short Garak run and one PyRIT run: count rows with NULL `run_id`, NULL `probe_id`, and unmatched prompts. The target is zero NULL `run_id`/`probe_id` on Garak and PyRIT rows. Garak rows with no match in `report.jsonl` are reported separately.

## Then (item 11, Fri Oct 9)
`detection_report.py` gets two numbers per run, v6 only: (1) of attacks graded successful by Garak/PyRIT, how many v6 flagged; (2) the share of benign-run traffic v6 flagged. (2) needs a benign replay run (the 210 support messages through `/chat`, `run_id benign_*`), which has not happened yet.

## Decisions and open questions
1. PyRIT grading: **decided**, we add a scorer.
2. Same-day repeats: **decided**, counter `-1`, `-2`, `-3`.
3. Benign replay with the 210 support messages: open. It is the only source of a live false-alarm number (Garak/PyRIT traffic is all attacks); the report must say the set is model-written and unreviewed.
