# Synthetic ATLAS alerts (40)

40 synthetic alerts, 10 per category (A, B, C, D): 19 pilot alerts plus 21 from batch 2.

## Files

In `synthetic_alerts/`:
- `alerts_final.jsonl`: the alerts the Mapper reads. It is the source of truth for the alert text. Classifier fields are NULL; only `ground_truth_category` is set.

In `evaluation/`, which holds the answers and must stay out of anything the Mapper container mounts:
- `ground_truth_final.json`: the answer key.
  - Framework cells (`atlas_technique_primary`, `atlas_techniques_supporting`, `attck_techniques`, `owasp_llm_2026`) hold bare IDs only.
  - Qualifiers such as "inferred", "secondary" or "attempted" are in `framework_notes`, keyed by ID.
  - `in_scope` is true for all 40.
  - `case_type` is Incident or Exercise.
- `review_log.csv`: one review row per alert. It sits here because some of its notes name the label terms that were removed from alerts.

The loader `synthetic_alerts/load_alerts.py` loads `alerts_final.jsonl` into alerts.db. It does not load the answer key or assign splits.

## Run order

Run these from `ai-attack-mapper/`:

1. `python3 synthetic_alerts/load_alerts.py --db alerts.db --schema alert_store/schema.sql`
   Use schema.sql on a fresh alerts.db. Re-running skips rows that are already loaded.
2. `alert_store/load_answer_key.py`, with `evaluation/ground_truth_final.json`
3. `alert_store/assign_split.py`

## Sources

The alerts are derived from public MITRE ATLAS case studies (https://atlas.mitre.org, data v2026.09) and public threat reports from Microsoft, Google GTIG, OpenAI, Anthropic, the FBI/IC3 and CNN. Every case has its `source_url` in `ground_truth_final.json`.

## Review

- **Drafting:** each alert was drafted by Shadi Atieh with an LLM from a fixed prompt template.
- **Faithfulness and label check:** Claude (claude-opus-5-5) checked every alert against its source on 2026-10-02 (pilot) and 2026-10-10 (batch 2), covering faithfulness, outcome wording and label leakage. The results are in `evaluation/review_log.csv`.
- **Human spot-check:** [TO CONFIRM: who, when, which alerts, what was checked]
