# AI Attack Mapper dashboard

One Streamlit app with a page per part of the pipeline: Overview, Attack campaigns, Detection,
Classification, Alert explorer, Auto-hardening, Playbooks, Evaluation. Read-only.

```
cd ai-attack-mapper
pip install -r dashboard_app/requirements.txt
streamlit run dashboard_app/app.py
```

Settings (environment variables, all optional):

| Variable | Default | What |
|---|---|---|
| `ALERTS_DB_PATH` | `alert_store/alerts.db` | alert store to read |
| `PROMPTS_DIR` | `testbed/prompts` | system prompt versions |
| `HARDENING_DIR` | `auto_hardening` | `history.jsonl` decisions, `utility_*.csv` checks |
| `REPORTS_DIR` | `attack_generation/reports` | `rounds.json` (invalid rounds) |
| `INVALID_ROUNDS` | `20261005_v6-2` | used when `rounds.json` is not present |

PowerShell: `$env:ALERTS_DB_PATH = "alert_store\alerts.db"`

## Data rules (in `data.py`, the only place they live)

- Live rows: `source = 'live'`; a round is a `run_id`. Kinds by prefix: `garak_`, `pyrit_` (attacks),
  `benign_` (harmless messages), `replayv` (replay tests), `utilv` (harmless checks). Pages use the first three.
- Harmless message: `probe_id` starts with `benign.` or `utility.`.
- Attack worked = `attack_succeeded = 1` (the attack tool's grading). Caught = detector flag set (`category` not NULL).
- Family = `probe_id` before the first dot.
- Rounds whose detector failed are left out of detection numbers (their attack grades are kept).
- Mapper calls come from `mapper_results` (or the alert row for production classifications).
- Classification reuses `mapper/matrix_data.py` and `mapper/matrix_render.py` for the framework matrix.

## Layout

Dark, SIEM-style console: each page has KPI tiles, titled panels (charts, top-N tables, event tables) and an
**About this page** button (top right) that holds the method notes, so the page itself shows only the numbers.
Events carry a severity: Critical = attack worked and was missed, High = worked and caught, Medium = failed but
flagged, Low = failed and not flagged, False alarm = harmless message flagged. The sidebar time range filters the
events on Overview, Attack campaigns, Detection and the Alert explorer.

Design changes should go in `ui.py` and the pages; keep `data.py` as the single source of the data rules.
The theme is in `ai-attack-mapper/.streamlit/config.toml` (start Streamlit from the `ai-attack-mapper` folder).
