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

1. `config.json` → `commands.classify`: Gladwin's live runner (with `--ids-file`), and `mapper_db` (the database it writes to).
2. `config.json` → `commands.import`: Aneeq's `import_mapper_results.py` (runs in the container).
3. `commands.playbooks` and `commands.evaluate` can stay `null`; those steps are skipped and noted in the summary.

Until 1 and 2 are set, a cycle stops at `classify` with a "waiting for" message and continues with `resume` once they are.

## Testing without touching alerts.db

```
python orchestrator/run_cycle.py snapshot --to cycle_test.db
python orchestrator/run_cycle.py start --base 1 --db cycle_test.db --attack-round <existing graded round> --stop-after gate
```

The snapshot uses the SQLite backup API. With `--attack-round` no new round is run; `--stop-after gate` stops before anything is stored on the testbed.

## Rules

- Only `approve` activates a version; it shows the diff and asks you to type the version number. A REJECT can be activated only with `--override-reason` (logged); an INCONCLUSIVE never (re-run the check instead).
- `hardening_applied` is set only for that cycle's eligible alerts, only after activation succeeded; `rollback` re-activates the base and clears it.
- All alert-store writes (annotate, Mapper import, hardening_applied) run inside the testbed container. Backups go to `alert_store/backups/` before the import and before approve.
- Seeds are recorded in `seeds_used.json` and cannot be reused by another cycle. Both verification rounds use the same seed and the same flags.
- An interrupted or failed round is marked INVALID in `rounds.json`; `resume` runs a new one. If the attack round's judge scores are missing, the round is replaced (the gate would skip it).
- The prompts the clauses were written from (eligible prompts of every cycle) count as seen, so `decide.py --variants fresh` only judges held-out prompts.
- `skip_families` comes from `config.json`; target families come from `harden.py`'s history entry for the new version.
- Two verification rounds plus the utility check take about 4–5 hours.

## Cycle folder

`cycles/<name>/`: `state.json`, `summary.md`, `decide.txt`, `approval.json` are committed; logs, `eligible.jsonl`, `live_results.jsonl`, the utility csv, id lists and the prompt diff stay local (`.gitignore`). Keep the local files: the next cycles read every cycle's `eligible.jsonl` for the seen set.
