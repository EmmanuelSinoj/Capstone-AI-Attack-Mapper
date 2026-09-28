# Detection v2 — Aneeq's version (live, in production)

**Built:** Sept 25, 2026 — part of the Live Attack Path track
**Approach:** raw Python regex (12 hand-written patterns, checked on both prompt and response) + the same Rebuff fuzzy-matching heuristic as v1, reused unmodified from Emmanuel's commit + Prompt-Guard-86M as a second-pass judge model (separate file, `judge.py`).

## Files

- `heuristics.py` — `check()` and `check_interaction()`, the heuristic half of detection
- `rebuff_heuristics.py` — identical logic to v1's, pulled directly from Emmanuel's commit rather than re-derived
- `judge.py` — Prompt-Guard-86M second-pass semantic check (currently inert — gated HF model, access not yet requested; degrades to heuristics-only with a logged warning)
- `logger.py` — combines heuristic + judge verdicts (`OR` logic), writes the alert to the shared Alert Store
- `evaluator_v2.py` — same methodology as v1's evaluator, run against the identical 500-prompt set

## What's different from v1

- 12 regex patterns instead of 7 (broader coverage, no substring-ban list)
- Checks the *response*, not just the prompt, using the same pattern set
- Adds the judge-model layer (not yet testable — blocked on Hugging Face access approval)
- Drops the output-side `NoRefusalLight` refusal-absence check v1 had

## Results (500-prompt labeled set, 70/30 split, held-out test)

| Threshold | Precision | Recall |
|---|---|---|
| 0.65 (current live default) | 0.966 | 0.373 |
| 0.50 (best F1) | 0.603 | 0.933 |

**5 attacks scored exactly 0** at any threshold — down from v1's 7, but the same underlying gap (roleplay/authority-framing attacks with no literal instruction-override wording).

## Known issue found during testing

At the live 0.65 threshold, "Can you ignore the typo in my last message and just answer the question?" scores 0.655 — a confirmed, reproducible false positive on an ordinary sentence.

## Status

Live in production (heuristics-only, judge model pending). The recommended upgrade is v4 (this plus input normalization; see `../detection_v4/README.md`). v3 was tried and rejected; see its README for why.

**Stress set** (`../stress_prompts.json`, 70 prompts, threshold 0.65): 2 of 40 normal prompts wrongly flagged, 3 of 30 novel attacks caught. Same novel-attack result as v1: the extra regex patterns raised recall on the 500-prompt set but did not help on differently-worded attacks.

## Run it

```bash
python evaluator_v2.py
```
No external dependencies beyond the standard library. Needs `labeled_prompts_500.json` in the parent `detection/` folder.
