# Plan: probe_id, run_id and attack_succeeded on every live row (Emmanuel items 7, 10, part of 8)

Status: plan only, written 2026-10-04 for Mon Oct 5. Nothing below is built yet. Emmanuel's date is Oct 10; live classification testing starts Oct 6, so the code lands before the first live run.

## What exists today
- `alerts` already has `probe_id`, `run_id` and `attack_succeeded` columns (`schema.sql`).
- `/chat` accepts an optional `probe_id` and passes it to `logger.py`. **`run_id` and `attack_succeeded` are never passed**, so they are NULL on every live row.
- Garak talks to `/chat` through its REST generator, which sends only the prompt. Garak's own files hold the probe name and the success result: `*.report.jsonl` (every attempt, with `probe_classname`) and `*.hitlog.jsonl` (the attempts that worked).
- PyRIT (`pyrit_runner.py`) has no scorer, so its outcomes are "undetermined". It now saves `reports/pyrit_run_<UTC>.json` (objective, outcome, response).

## run_id and rounds
- A **round** is one test session: the attack run(s) plus the benign run that goes with them. The round token is `<YYYYMMDD>_<DETECTION_VERSION>-<n>`, e.g. `20261006_v6-1`; `n` counts rounds that day (`-1`, `-2`, `-3`; decided 2026-10-04).
- `run_id` = `<tool>_<round token>`: `garak_20261006_v6-1`, `pyrit_20261006_v6-1`, `benign_20261006_v6-1`. All runs in a round share the same token, so the report pairs them by the token after the first underscore.
- **Rule (decided 2026-10-04): an attack run must be accompanied by a benign run in the same round.** The campaign runner starts both under one round token; the report marks a round "incomplete" if it has attack rows but no benign rows (no false-alarm number) and shows a warning.
- Set once per run by the runner and sent with every request: `/chat` gets an optional `run_id` field and `logger.py` writes it. For Garak the runner writes it into the REST generator's request body template; for PyRIT and the benign replay it is part of the request.

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

## Status 2026-10-04 (code written, NOT yet tested end to end)
Built: `run_id` accepted by `/chat` and written by `logger.py`; `attack_generation/rounds.py` (round tokens, one run per tool per round); `garak_runner.py` and `pyrit_runner.py` tag every request with `run_id` (PyRIT also `probe_id` per objective); `benign_replay_runner.py`; `run_round.py` (Garak + PyRIT + benign under one round); `annotate_run.py` (fills Garak `probe_id` and `attack_succeeded`; dry run verified on the 2 Oct session: 5,109 of 5,114 rows matched). Not built: the PyRIT scorer (decided: we add one), the report extension (item 11).
Needs a restart of the testbed container before the first live run, and a short trial run (`run_round.py --probes promptinject --benign-limit 20`).

### "Worked" has three definitions in play; pick one before the numbers are quoted
For the 2 Oct session: (a) the report's current method counts a row as worked if its prompt appears in ANY Garak hit log (all sessions): 1,058 rows; (b) prompt appears in THIS run's hit log: 852 rows; (c) this run's hit log by (prompt, output) pair, i.e. that exact generation: 612 rows. `annotate_run.py` writes (c), the strictest. (a) overstates when the same prompt succeeded in another session. Recall = flagged / worked, so the choice moves the headline number.

## Status 2026-10-04 night (item 11 built)
Round plumbing tested live (round 20261004_v6-3: 768 Garak rows annotated, 231 graded successful; PyRIT scored 3/4 by `pyrit_scorer.py`; benign 20 rows). `detection_report.py --round <token>` now adds section 0: per tool, successful attacks flagged by v6 (prompt-only rule) with 95% Wilson CI, benign flag rate with CI, warnings for missing runs, ungraded rows, small benign sample, and the weak PyRIT rule. In round mode "worked" = stored `attack_succeeded`, so Garak counts match the round summary (231, not the all-sessions hit-log count).

## Item 12 built 2026-10-04 (system-prompt versions + replay runner), NOT yet run against the live testbed
- Testbed (`testbed/app.py`): numbered, append-only prompt versions in `testbed/prompts/system_prompt_v<N>.txt` (v1 = the current prompt). `GET /prompts` lists them (+sha), `POST /prompts {text, activate}` stores the NEXT number (refuses to overwrite), `POST /prompts/activate {version}` copies a stored version into `system_prompt.txt` (the active prompt, default for `/chat`). `/chat` accepts `use_system_prompt_version` to answer with a stored version without activating it; the version actually used is returned and logged (`system_prompt_version`) on every alert row. Auto-Hardening (Gladwin) should call `POST /prompts` instead of editing `system_prompt.txt` in place.
- Needs the `prompts/` bind mount (in the local `docker-compose.override.yml`; belongs in the compose-path-fix PR) and `docker compose up -d testbed`.
- `build_replay_set.py`: freezes attacks that worked (Garak hit logs with trigger strings, stratified per probe, seed 42; optional paraphrase file) into `replay_sets/replay_set_<name>.json`. `replay_runner.py --set ... --versions 1,2 --repeats 3`: one run id per version (`replayv<N>_<round>`), requests pinned to that version, graded by trigger strings (Garak's own rule), summary with Wilson intervals and the change between versions. `annotate_run.py <round>` copies the grades into the alert store.
- Limits: paraphrases not generated yet (set has originals only); grading only covers probes that carry trigger strings (promptinject-style); the round report (`detection_report.py --round`) does not show replay runs yet.
