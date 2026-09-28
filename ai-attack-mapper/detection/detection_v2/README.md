# Detection v2 — Aneeq's version (live in production)

12 hand-written regex patterns (checked on both prompt and response) + the Rebuff fuzzy matcher + Prompt-Guard-86M as a second-pass judge model (`judge.py`, currently inert — gated HF model, access not yet requested).

## Results — all 500 prompts (250 attack, 250 normal), no split

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 0.50 | 227 | 156 | 94 | 23 | 0.593 | 0.908 | 0.717 |
| 0.60 | 98 | 5 | 245 | 152 | 0.951 | 0.392 | 0.555 |
| **0.65** | **84** | **5** | **245** | **166** | **0.944** | **0.336** | **0.496** |
| 0.70 | 71 | 0 | 250 | 179 | 1.000 | 0.284 | 0.442 |

Zero-score attacks: 23 of 250.

## Stress set

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **0.65** | **3** | **2** | **38** | **27** | **0.600** | **0.100** | **0.171** |

## Known issue

A prompt with zero-width characters inserted between every letter fully evades this version's regex layer. Fixed in v4.

## Status

Live in production (heuristics-only, judge model pending). Recommended upgrade is v4 (this plus input normalization). v3 was tried and rejected; see its README for why.

## Run

```bash
python evaluator_v2.py              # all 500 prompts, sweep + fixed threshold 0.65
python evaluator_v2.py -v
python evaluator_v2.py --split 0.7  # legacy: reproduces the earlier 70/30 numbers
```