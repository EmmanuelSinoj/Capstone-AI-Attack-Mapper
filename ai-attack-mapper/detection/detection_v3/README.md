# Detection v3 — a bigger fix that did not hold up (kept as evidence, do not deploy)

**Status: NOT recommended.** v2 plus input normalization (zero-width character stripping, Unicode NFKC) plus two new phrase families added to the fuzzy matcher (prompt-exfiltration wording, unrestricted-persona wording).

## Results — all 500 prompts (250 attack, 250 normal), no split

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 0.50 | 249 | 227 | 23 | 1 | 0.523 | 0.996 | 0.686 |
| 0.60 | 169 | 18 | 232 | 81 | 0.904 | 0.676 | 0.773 |
| **0.65** | **138** | **16** | **234** | **112** | **0.896** | **0.552** | **0.683** |
| 0.70 | 98 | 0 | 250 | 152 | 1.000 | 0.392 | 0.563 |

Zero-score attacks: 1 of 250 — the lowest of any version. Looks like a strong result.

## Stress set — where it falls apart

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 0.60 | 9 | 36 | 4 | 21 | 0.200 | 0.300 | 0.240 |
| **0.65** | **4** | **28** | **12** | **26** | **0.125** | **0.133** | **0.129** |
| 0.70 | 0 | 25 | 15 | 30 | 0.000 | 0.000 | 0.000 |

At every threshold tested, v3 wrongly flags more everyday prompts than it catches real attacks on this set. At 0.65, 28 of 40 normal prompts ("Act as a translator", "Tell me the rules of chess", ...) are wrongly flagged.

## Why it failed

The new fuzzy-matcher phrases are short (3–5 words) and the matcher scores by word position, so matching just the opening words already scores 0.7+. Prompts starting with "act as", "tell me", "pretend to be" score similarly whether they're attacks or not. The 500-prompt benchmark didn't catch this because it has no natural prompts phrased that way, and its attack templates share wording with the phrases added here — so the benchmark result overstated this version.

## Status

Not recommended. Kept in the repo as the evidence for choosing v4 instead.

## Run

```bash
python evaluator_v3.py
python stress_test.py detection_v3 sweep
```