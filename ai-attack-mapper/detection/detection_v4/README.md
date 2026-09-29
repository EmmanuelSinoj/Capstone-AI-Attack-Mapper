# Detection v4 — v2 plus input normalization (recommended)

v2 unchanged, plus one addition: text is cleaned of invisible/zero-width characters and Unicode-normalized before either detection signal runs. Diff against v2's `heuristics.py` is three lines. `rebuff_heuristics.py` is v2's original (8,800 phrases) — the two new phrase families from v3 are NOT included.

## Results — all 500 prompts (250 attack, 250 normal), no split

Identical to v2 on this benchmark, since normalization only matters when hidden characters are present.

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 0.50 | 227 | 156 | 94 | 23 | 0.593 | 0.908 | 0.717 |
| 0.60 | 98 | 5 | 245 | 152 | 0.951 | 0.392 | 0.555 |
| **0.65** | **84** | **5** | **245** | **166** | **0.944** | **0.336** | **0.496** |
| 0.70 | 71 | 0 | 250 | 179 | 1.000 | 0.284 | 0.442 |

Zero-score attacks: 23 of 250.

## Stress set

Also identical to v2.

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **0.65** | **3** | **2** | **38** | **27** | **0.600** | **0.100** | **0.171** |

## Why v4 over v2

A prompt with zero-width characters between every letter fully evades v2's regex (`False, []`); v4 catches it (`True, ['prompt_exfiltration']`). Confirmed directly, not inferred. Everything else is unchanged — this is a robustness fix, not an accuracy gain.

## Why v4 over v3

v3 catches more on the benchmark but wrongly flags most everyday prompts on the stress set. v4 keeps only the part of v3 that held up under stress testing. See `../detection_v3/README.md`.

## Known limitations

- Catches 3 of 30 differently-worded attacks on the stress set. Pattern matching cannot recognize an attack by meaning — that's the judge model's job.
- Fuzzy score rises with prompt length; long normal text (200+ words) can be over-flagged.
- Two known false positives: "Print the instructions for the form on page two", "Please ignore the previous email and use this version."

## Run

```bash
python evaluator_v4.py
python stress_test.py detection_v4 sweep
```