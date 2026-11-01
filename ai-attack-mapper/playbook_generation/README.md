# Playbook Generation (WBS 6.1)

**Owner:** Shadi · **Status:** ready for the first full cycle

Writes a defense playbook into `alerts.playbook` for every alert with a valid Mapper result. The dashboard's Playbooks page reads it.

## How a playbook is built

1. **Control family (Category E):** picked in code from `controls_crosswalk.json` by the Mapper's category and sub-cluster. The model never picks it, so every playbook has a control family from the crosswalk (D2 US7 acceptance).
2. **Text:** a model writes the summary and 3–5 containment steps for that alert. It gets the Mapper result, the alert text and the crosswalk entry. The default is Claude Haiku 5.5 through `mapper/client.py`, the same model and API key as the Mapper.
3. **Fallback:** if the reply is unusable after one retry, the crosswalk's own steps are used. `generator.method` in the playbook says `llm`, `template` or `template-fallback`.

Out-of-scope alerts get a short "no action" playbook without a model call. The answer key is never read: alert text comes through the `mapper_input` view.

## Commands

Run from `ai-attack-mapper/`.

```
# 1. host: reads the DB read-only, writes <out-dir>/playbooks.jsonl and playbooks_log.json
python playbook_generation/generate_playbooks.py generate --db my_test.db \
    --mapper-run <mapper run id> [--round <round token>] --out-dir <folder>

# 2. container: backs up the DB, then UPDATE alerts SET playbook = ? WHERE id = ?
python3 /app/playbook_generation/generate_playbooks.py apply --db <db in container> \
    --in <folder in container>/playbooks.jsonl
```

| Option | What |
|---|---|
| `--mapper-run` | `mapper_results.run_id`; repeat the flag for several runs. Only `valid_json = 1` rows; with repeats, the first valid repeat |
| `--round` | only live alerts of `garak_<token>`, `pyrit_<token>`, `benign_<token>` |
| `--backend` | `claude` (default), `ollama`, or `none` (crosswalk steps only, no API calls) |
| `--model` | default `MAPPER_CLAUDE_MODEL` (`claude-haiku-5-5`); env `PLAYBOOK_MODEL` also works |
| `--workers` | parallel model calls, default 4 |
| `--resume` | keep playbooks already in the output file (re-run after an interruption) |
| `--limit N` | first N alerts only, for testing |
| `apply --dry-run` | count what would change, write nothing |
| `apply --backup-dir` | where the backup goes (default: next to the DB) |

`apply` refuses the whole file, writing nothing, if any alert id is unknown, a record is malformed, or a playbook has fewer than 2 containment steps. It writes everything in one transaction. It uses the standard library only.

`generate` needs `requests` (already in `mapper/requirements.txt`) and `ANTHROPIC_API_KEY` in `.env`, unless `--backend none`.

## Orchestrator config (`commands.playbooks`)

```json
"playbooks": {"run": [
  ["{python}", "playbook_generation/generate_playbooks.py", "generate", "--db", "{db}", "--mapper-run", "{mapper_run}", "--out-dir", "{cycle_dir}"],
  ["python3", "/app/playbook_generation/generate_playbooks.py", "apply", "--db", "{db_c}", "--in", "{cycle_dir_c}/playbooks.jsonl"]
]}
```

The testbed container needs `./playbook_generation:/app/playbook_generation` mounted.

## Files

| File | What |
|---|---|
| `generate_playbooks.py` | `generate` and `apply` |
| `controls_crosswalk.json` | Category E control family + baseline containment steps for each of the 16 Mapper sub-clusters, a default per category, and an out-of-scope entry. **Draft v1: team review welcome.** |
| `test_generate_playbooks.py` | 17 tests, stdlib only, no API calls: `python3 playbook_generation/test_generate_playbooks.py` |

## Playbook JSON

```json
{"summary": "...", "containment_steps": ["...", "..."], "recommended_control": "...",
 "control_description": "...", "severity": "High", "category": "B", "sub_cluster": "...",
 "lifecycle_phase": "...", "framework_ids": {"atlas": [], "attck": [], "owasp_llm": []},
 "source": "live", "mapper_run": "...",
 "generator": {"version": "pbgen-v1", "method": "llm", "model": "claude-haiku-5-5", "crosswalk": "crosswalk-v1-draft"},
 "generated_at": "..."}
```

Severity is recomputed with `mapper/severity.py`, so it matches the dashboard.
