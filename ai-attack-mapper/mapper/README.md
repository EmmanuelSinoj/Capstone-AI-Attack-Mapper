# Mapper (Classification Engine)

Owner: Gladwin Mathews (Classification & Defense). Classifies an alert against the
five-category taxonomy and MITRE ATT&CK v20 / MITRE ATLAS 2026.09 / OWASP LLM Top 10
(2026), with a deterministic severity. Prompt-based (no fine-tuning); the same prompt
runs on a local Ollama model or Claude.

## Model Selection Pilot result (Oct 21, 2026)

Prompt v6 (fingerprint 81ed96bf5722). Dev = 16 alerts, held-out = 24 alerts.

| Model | Dev category | Held-out category | Held-out sub-cluster | Held-out Brier | Dev cost (3 repeats) |
|---|---|---|---|---|---|
| llama3:8b (Ollama, free) | 62.5% | not run | - | - | $0 |
| Sonnet 5.5 (primary, frozen) | 100% (API) / 93.8% (chat) | **91.7%** (chat) | 87.5% | 0.087 | $0.38 |
| Haiku 5.5 (secondary, frozen) | 100% | **91.7%** | 87.5% | 0.087 | $0.04 |

**Production model: `claude-haiku-5-5`.** It ties Sonnet 5.5 on accuracy, consistency and
calibration at about one tenth of the cost. It is the default in `client.py`; set
`MAPPER_CLAUDE_MODEL` in `.env` to override. Both models miss 2 of 24 held-out alerts
(Haiku: one B alert read as A, one C alert read as D, on every repeat). ATT&CK any-match is the weakest
framework score on held-out (~57-60%). Haiku's held-out was run twice by mistake: the first
run (`pilot_20261021T182711...`) is the reported one; the second gave the same category result
and is logged in `evaluation/heldout_lock.json`. A second model can be frozen alongside the
primary with `freeze --secondary-reason "..."`; it is reported separately.

## Live classification testing (Oct 24, 2026)

Frozen Mapper (Haiku 5.5, prompt v6, fingerprint 81ed96bf5722) on 299 real live alerts from
`alerts_full_PR9.db`, valid rounds only (`garak/pyrit_20261004_v6-3`, `garak/pyrit_20261005_v6-4`,
benign rows). Run id `pilot_20261024T120031_claude_claude-haiku-5-5_v6_live`, 1 repeat, results in
`mapper_results`; run report in `evaluation/`. Sample: shuffled, distinct inputs, seed 42.

| Group | n | B | C | No attack | A | API refused |
|---|---|---|---|---|---|---|
| Attack worked, detector flagged | 100 | 92 | 7 | 1 | 0 | 0 |
| Attack worked, detector missed | 60 | 41 | 3 | 13 | 1 | 2 |
| Attack failed, flagged | 40 | 36 | 1 | 0 | 0 | 3 |
| Attack failed, missed | 40 | 27 | 5 | 8 | 0 | 0 |
| Harmless, flagged | 4 | 0 | 2 | 2 | 0 | 0 |
| Harmless, unflagged | 55 | 0 | 2 | 52 | 1 | 0 |

- Attacks called B: 196 / 240 (82%). By family: promptinject 81/89, dan 62/67, encoding 51/80
  (19 encoding attacks read as "no attack").
- Harmless messages called B: 0 / 59. The 5 wrong calls on harmless messages were C or A, at
  confidence 0.40-0.65. With 59 messages, the true rate can still be up to about 5%.
- C on attacks: 16. Two are system-prompt leak attempts (PyRIT), which prompt v6 correctly
  calls C; the other 14 are hijack or encoding attacks and count as misses.
- API refusals (5 alerts) count as Mapper failures.

**Confidence threshold for the auto-hardening gate: 0.7** (`gate.py --require-mapper
--min-confidence 0.7`). It keeps 104 of 160 successful attacks with no harmless message called B.
0.8 keeps 66; confidence scores cluster at 0.7 and 0.85.

**The Mapper confirms; it does not choose the countermeasure.** It tags nearly every injection
and jailbreak with both AML.T0051 and AML.T0054, so the Mapper-based clause choice
(`harden.py --select mapper`) would give 43 of 51 promptinject attacks the jailbreak clause.
dan (36/40) and encoding (12/12) agree. The clause stays chosen by probe family.

## Status (Oct 21, 2026)

- Uses the shared alert store v3 (Shadi's update): reads `db.get_mapper_input()` /
  `db.get_mapper_queue()`, writes `db.save_classification()` (production) or
  `db.save_mapper_result()` (pilot). The Mapper never sees the answer key, and the
  detector's `category` flag and `confidence` are never overwritten.
- Model Selection Pilot harness built (`pilot.py`) on the 40 synthetic alerts with the
  fixed split (seed 42, 40% dev -> 16 dev / 24 held-out). Held-out is locked in code.
- Reference data rebuilt from ATLAS 2026.09 (v6 format). The old `dist/ATLAS.yaml` was
  frozen by MITRE at 5.6.0 and missing IDs the prompt and answer key use.
- Prompt v2: every ID in the reference section is a real ID; no placeholder suffixes
  (`.00x`, `.x`) for the model to copy.
- Ollama calls now set `num_ctx` 8192 and temperature 0 (Claude: temperature 0). The
  prompt is ~3,000 tokens; a 2,048-token default window silently cut it.
- Prompt v4 (from the first dev run, llama3.2:latest on v3: category 37.5%, the model
  labelled most alerts "Prompt injection & jailbreaking" or "Agent tool & API misuse" and
  copied whole ID lists): decision order rewritten, adversarial / confidence guidance,
  full ATLAS 2026.09 catalog in place of per-category ID lists. classify.py now
  normalizes framework IDs deterministically (strips appended names, splits joined IDs,
  moves IDs to the right framework); `replies_needing_id_cleanup` reports how often.
- Revoked ATT&CK IDs in the key (T1656, T1562.001) are mapped to their v20 replacements
  on both sides before scoring.
- Auto-Hardening (`auto_hardening/`) is built on branches `aneeq-auto-hardening` and
  `emmanuel-hardening-v2`; the Mapper is its confirmation gate (B, confidence >= 0.7).

## Files

| File | What it does |
|---|---|
| `prompt.py` | System prompt, `PROMPT_VERSION`, `prompt_fingerprint()`. Keep in sync with `AI_Attack_Mapper_Prompt_v1.md`. Bump the version on any change. |
| `client.py` | Ollama / Claude calls. Reads `CLASSIFIER_MODEL`, `OLLAMA_HOST`, `ANTHROPIC_API_KEY`, `OLLAMA_NUM_CTX` from the environment or the repo `.env`. |
| `schema.py` | Validates a reply (an in-scope reply must have category A-D). |
| `severity.py` | Deterministic severity. Not stored; recomputed on read with `severity_from_fields()`. |
| `classify.py` | `classify_alert()` and `classify_alert_full()` (raw text, tokens, one retry after an unusable reply). |
| `pipeline.py` | Production: classify `get_mapper_queue()` and `save_classification()`. |
| `pilot.py` | Model Selection Pilot on dev / held-out (below). |
| `framework_reference.py` | Resolves IDs against real ATT&CK / ATLAS / OWASP data; `parse_id_list()` reads the JSON ID columns. |
| `build_framework_reference.py` | Rebuilds `data/framework_reference_data.json` (ATT&CK STIX + ATLAS v6 + OWASP 2026 table). |
| `matrix_data.py`, `matrix_render.py` | The visual ATT&CK / ATLAS / OWASP matrix. |
| `dashboard_app.py` | Streamlit dashboard: production results, pilot scores, matrix, alert detail. |
| `evaluate.py`, `test_alerts.py`, `dry_run_test.py`, `seed_alerts.py`, `live_ollama_test.py` | Older checks on the 4 hand-written alerts. Not for reported numbers. |

## Pilot: dev / held-out

Set up once (take a copy of `alerts.db` first), from `ai-attack-mapper/`:

```
python3 synthetic_alerts/load_alerts.py --db alert_store/alerts.db --schema alert_store/schema.sql
cd alert_store
python load_answer_key.py ../evaluation/ground_truth_final.json
python assign_split.py --seed 42 --dev-fraction 0.4      # must report 16 dev, 24 held-out
cd ..
python -m mapper.pilot status
```

Tune on dev:

```
python -m mapper.pilot run --backend ollama --model llama3.2:latest
python -m mapper.pilot run --backend claude --repeats 3
python -m mapper.pilot errors --run-id <dev run id>       # read dev errors, change the prompt, bump PROMPT_VERSION
python -m mapper.pilot score                              # all runs; JSON copy in evaluation/
```

Then freeze and run held-out once:

```
python -m mapper.pilot freeze --backend claude --model claude-haiku-5-5 --from-run <dev run id>
python -m mapper.pilot run --backend claude --model claude-haiku-5-5 --repeats 3 --split heldout
```

The held-out run is refused before `freeze`, if the model or prompt text differs from the
freeze, and a second time unless `--rerun-reason "..."` is given (logged in
`evaluation/heldout_lock.json` for the write-up). `errors` refuses held-out runs.

What `score` reports per run and split: valid-JSON rate (and first-try rate), category
accuracy (over valid replies, and strict: unusable = wrong), sub-cluster (exact and
normalized), in-scope and adversarial accuracy, framework IDs three ways (ATLAS
primary match, any-overlap per framework, set precision/recall), malformed-ID rate,
confidence calibration (mean confidence vs. accuracy, Brier, 5-bin ECE), repeat
consistency, and a confusion matrix. Dev has 4 alerts per category: one alert = 6.25
points of dev accuracy.

## Dashboard

```
pip install -r mapper/requirements.txt
streamlit run mapper/dashboard_app.py
```

## Notes for the team

- Live path (Aneeq / Emmanuel): `docker-compose.yml` and `testbed/Dockerfile` point at a
  `live_attack_path/` folder that doesn't exist, and `testbed/app.py` calls
  `log_interaction()` with 5 arguments while `detection_v2`'s logger takes 4 (the
  TypeError is swallowed by `_log_interaction_safe`). Until fixed, no live alerts reach
  the store.
- Sub-cluster scoring in `mapper_scores` is exact string equality; `pilot.py` also reports
  a normalized match. Listing the answer key's sub-cluster names in the prompt would make
  the exact score meaningful.
