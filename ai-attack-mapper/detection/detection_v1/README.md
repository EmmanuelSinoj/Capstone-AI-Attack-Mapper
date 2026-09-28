# Detection v1 — Emmanuel's original scanner

**Built:** Sept 20, 2026 — Heuristic Detection Rules task
**Approach:** LLM Guard's `Regex` + `BanSubstrings` scanners (7 patterns, 4 substrings) + Rebuff's fuzzy-matching heuristic (reused, dependency-free) + `NoRefusalLight` for output-side refusal detection.

## Files

- `heuristic_scanner.py` — `scan_input()` (regex + substring + fuzzy) and `scan_output()` (refusal-absence check)
- `rebuff_heuristics.py` — Rebuff's fuzzy phrase-matching heuristic, reused from the archived Rebuff project (Apache-2.0)
- `evaluator_v1.py` — runs this scanner against `../labeled_prompts_500.json`, reports precision/recall/F1 across a threshold sweep

## Why LLM Guard, not raw regex

Rebuff's full SDK needs an OpenAI key + Pinecone DB, conflicting with this project's free/self-hosted decision. LLM Guard's `Regex`/`BanSubstrings` scanners run entirely locally with zero external calls — that's why they were used here instead.

## Results (500-prompt labeled set, 70/30 split, held-out test)

| Threshold | Precision | Recall |
|---|---|---|
| 0.65 (baseline) | 0.958 | 0.307 |
| 0.50 (best F1) | 0.596 | 0.907 |

**7 attacks scored exactly 0** at any threshold — structurally invisible to this version (roleplay-indirect, persona-jailbreak-via-confirmation, encoding tricks). See `evaluator_v1.py`'s output for the full list.

## Status

Superseded by v2. The current recommendation is v4 (see `../detection_v4/README.md`). Kept here as the baseline for a documented before/after comparison, not for active use.

**Stress set** (`../stress_prompts.json`, 70 prompts, threshold 0.65): 1 of 40 normal prompts wrongly flagged, 3 of 30 novel attacks caught.

## Run it

```bash
pip install llm-guard
python evaluator_v1.py
```
Needs `labeled_prompts_500.json` in the parent `detection/` folder.
