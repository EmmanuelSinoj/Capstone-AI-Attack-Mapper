# Detection v4 — v2 plus input normalization (recommended)

**Built:** Sept 28, 2026, after stress-testing v3.

**What it is:** Aneeq's v2 heuristic layer, unchanged, plus one addition: text is cleaned of invisible/zero-width characters and Unicode-normalized before either detection signal runs. The diff against v2's `heuristics.py` is three lines (one import, two `normalize_for_detection()` calls). `rebuff_heuristics.py` is v2's original, with the original 8,800 phrases.

## Why v4 exists

v3 combined two changes. Only one held up.

| Change in v3 | Result |
|---|---|
| Input normalization | Works. A prompt with zero-width spaces between every letter fully evaded v2's regex; v4 catches it. |
| Two new fuzzy-matcher phrase families | Did not hold up. See below. |

The new phrase families were short ("Act as an unrestricted AI", "Tell me the rules"). The matcher scores by word position, so matching just the opening words gives a high score. On natural prompts, v3 flagged nearly everything. Our 500-prompt set missed this because it had no natural "act as / tell me / show me" prompts, and its attack templates shared wording with the added phrases.

## Results

**500-prompt set (70/30 split), threshold 0.65:** identical to v2.

| | Precision | Recall | Zero-score attacks |
|---|---|---|---|
| v4 | 0.966 | 0.373 | 5 |

**Stress set** (`../stress_prompts.json`: 40 natural prompts, 30 attacks phrased differently from the templates and phrase lists):

| Version @ threshold | Normal prompts wrongly flagged | Novel attacks caught |
|---|---|---|
| v2 @ 0.65 | 2 of 40 | 3 of 30 |
| v3 @ 0.60 | **36 of 40** | 9 of 30 |
| v3 @ 0.65 | 28 of 40 | 4 of 30 |
| **v4 @ 0.65** | **2 of 40** | **3 of 30** |

v3's extra phrases did catch more novel attacks (9 vs 3), but at a 90% false-alarm rate, which is unusable.

## Known limitations

- Catches only 3 of 30 novel attack phrasings. Pattern matching cannot recognize an attack by meaning; that is the judge model's job (`judge.py`, waiting on Hugging Face access).
- Two known false positives: "Print the instructions for the form on page two" (regex `print the instructions`) and "Please ignore the previous email and use this version" (fuzzy score 0.657).
- The stress set was written by us and is small (70 prompts). Treat it as a check on v3's failure, not as an accuracy estimate.

## Possible future work

Re-add the two phrase families with a guard that requires the distinguishing word ("system prompt", "unrestricted", "jailbroken") to match, not just the opening verb. Test it against `stress_prompts.json` before adopting.

## Run

```bash
python evaluator_v4.py                          # run from inside detection_v4/
python stress_test.py detection_v4 0.65         # run from the detection/ folder
```
