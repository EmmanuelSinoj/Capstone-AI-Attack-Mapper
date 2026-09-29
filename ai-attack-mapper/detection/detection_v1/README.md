# Detection v1 — original (baseline, not recommended)

LLM Guard's Regex + BanSubstrings scanners (7 patterns, 4 banned phrases) plus the Rebuff fuzzy-matching heuristic.

## Results — all 500 prompts (250 attack, 250 normal), no split

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 0.50 | 222 | 156 | 94 | 28 | 0.587 | 0.888 | 0.707 |
| 0.60 | 84 | 5 | 245 | 166 | 0.944 | 0.336 | 0.496 |
| **0.65** | **68** | **5** | **245** | **182** | **0.932** | **0.272** | **0.421** |
| 0.70 | 53 | 0 | 250 | 197 | 1.000 | 0.212 | 0.350 |

Zero-score attacks (no threshold catches these): 28 of 250.

## Stress set — 30 attacks worded differently from the benchmark, 40 everyday prompts

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **0.65** | **3** | **1** | **39** | **27** | **0.750** | **0.100** | **0.176** |

## Status

Baseline. Superseded by v2. Recommended version is v4.

## Run

```bash
pip install llm-guard
python evaluator_v1.py              # all 500 prompts, sweep + fixed threshold 0.65
python evaluator_v1.py -v           # also list missed attacks
python evaluator_v1.py --split 0.7  # legacy: reproduces the earlier 70/30 numbers
```