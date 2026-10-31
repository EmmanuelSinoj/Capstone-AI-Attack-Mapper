# Full-cycle script (WBS 8.2)

`run_cycle.py` runs one auto-hardening cycle end to end and stops before anything goes live. Run it from the `ai-attack-mapper` folder on the testbed machine.

```
python orchestrator/run_cycle.py start --base 1 --seed 42 --verify-seed 43 --dry-run   # print the plan
python orchestrator/run_cycle.py start --base 1 --seed 42 --verify-seed 43
python orchestrator/run_cycle.py status
python orchestrator/run_cycle.py resume --cycle <name> [--only <step>] [--stop-after <step>]
python orchestrator/run_cycle.py approve --cycle <name> [--override-reason "..."]
python orchestrator/run_cycle.py rollback --cycle <name>
python orchestrator/run_cycle.py snapshot --to cycle_test.db
```

Steps: attack, grade, classify, import, playbooks, gate, harden, verify_candidate, grade_candidate, verify_base, grade_base, utility, decide, evaluate, summary. The full list with the exact command each step runs is in the docstring of `run_cycle.py`; `--dry-run` prints them with real paths.

## Before the first real run

1. **Machine settings** in `config.json` on the testbed machine:
   - `root`: the folder the LIVE stack uses that holds `attack_generation/`, `auto_hardening/`, `alert_store/`, `testbed/` (e.g. `live_attack_path`). `compose_dir`: where `docker-compose.yml` is. Both `null` = this clone. They must point at the tree the running testbed writes to, or rounds and annotate use different databases.
   - `python`: the venv Python that has Garak and PyRIT (`run_round.py` starts them with it).
2. `commands.classify`: Gladwin's live runner with `--ids-file {ids_file}`. It must leave its run in `{mapper_db}` (= `<cycle folder>/mapper_results.db`, one run per file), either by writing there directly or with a second command such as `export-run --run-id {mapper_run} --out {mapper_db}`. Several commands are written as a list of lists.
3. `commands.import` is already set: Aneeq's `import_mapper_results.py --expect-round <round> --apply` in the container (it checks the ids and backs up the alert store first).
4. `commands.playbooks` and `commands.evaluate` can stay `null`; those steps are skipped and noted in the summary.

Until 2 is set, a cycle stops at `classify` with a "waiting for" message and continues with `resume` once it is.

## Testing without touching alerts.db

```
python orchestrator/run_cycle.py snapshot --to cycle_test.db
python orchestrator/run_cycle.py start --base 1 --db cycle_test.db --attack-round <existing graded round> --stop-after gate
```

The snapshot uses the SQLite backup API. With `--attack-round` no new round is run; `--stop-after gate` stops before anything is stored on the testbed.

## Rules

- Only `approve` activates a version; it shows the diff and asks you to type the version number. A REJECT can be activated only with `--override-reason` (logged); an INCONCLUSIVE never (re-run the check instead).
- `hardening_applied` is set only for that cycle's eligible alerts, only after activation succeeded; `rollback` re-activates the base and clears it.
- All alert-store writes (annotate, Mapper import, hardening_applied) run inside the testbed container. The import script backs up the alert store itself; `approve` makes a backup in `alert_store/backups/` first.
- Seeds are recorded in `seeds_used.json` and cannot be reused by another cycle. Both verification rounds use the same seed and the same flags.
- An interrupted or failed round is marked INVALID in `rounds.json`; `resume` runs a new one. If the attack round's judge scores are missing, the round is replaced (the gate would skip it).
- The prompts the clauses were written from (eligible prompts of every cycle) count as seen, so `decide.py --variants fresh` only judges held-out prompts.
- `skip_families` comes from `config.json`; target families come from `harden.py`'s history entry for the new version.
- Two verification rounds plus the utility check take about 4–5 hours.

## Cycle folder

`cycles/<name>/`: `state.json`, `summary.md`, `decide.txt`, `approval.json` are committed; logs, `eligible.jsonl`, `live_results.jsonl`, the utility csv, id lists and the prompt diff stay local (`.gitignore`). Keep the local files: the next cycles read every cycle's `eligible.jsonl` for the seen set.
