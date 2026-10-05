# Detection v6

`DETECTION_VERSION = "v6"` in `__init__.py`. The code stays in `ai-attack-mapper/detection/` (imports and Docker mounts depend on that path). `detection_v1` to `detection_v4` are Emmanuel's earlier comparison folders; v5 is his PR #3 (38 patterns, fuzzy matcher still on).

## What v6 is

A prompt is flagged if **either**:

1. it matches one of **43 exact patterns** (`heuristics.py`): v5's 38 plus 5 `encoding_smuggling` patterns, after Unicode and zero-width clean-up and after decoding base64, hex and ROT13; **or**
2. the Prompt-Guard-86M **JAILBREAK log-odds is at least 9.1** (`judge.py`, `JUDGE_THRESHOLD`, default 9.1; not set in `.env` or `docker-compose.yml`). Log-odds = `logit_JAILBREAK - logsumexp(logit_BENIGN, logit_INJECTION)` on raw logits in float64. Prompts over 512 tokens are scored in 510-token windows and the highest window counts.

The judge scores the **prompt only**. Responses are covered by the patterns and by the system-prompt-leak check (`heuristics._check_system_prompt_leak`). The fuzzy matcher is removed (`rebuff_heuristics.py` deleted).

When a detector fires, `logger.py` writes `category = "B"` (live prompt injection in the Mapper's A-E taxonomy). `detector` reads like `heuristic:persona_jailbreak | judge:prompt=JAILBREAK(lo=9.44)`, `heuristic:clean | judge:prompt=BENIGN(lo=3.10)`, or `... | judge:unavailable`.

## How 9.1 was chosen

Everything below uses the 700 JailbreakHub training prompts and the same 5-fold split as Emmanuel's `kfold_validate.py` (rows sorted by index, `random.Random(42)` shuffle of attacks then normal prompts, `fold[k] = attacks[k::5] + normal[k::5]`). Locked-test prompts were not used to choose it.

- **Rule (combined rule, patterns OR judge):** take the cutoff with the highest average training-fold accuracy; thresholds within 1 point of that accuracy are treated as tied, and the tie goes to the lower false-alarm rate.
- **Result:** accuracy is flat from 8.7 to 9.1 (73.3% to 73.9%). 8.8 is the raw maximum at 73.9%, 0.2 points above 9.1 (73.7%), but it flags more normal prompts (23.1% versus 19.7%) and catches more attacks (70.9% versus 67.1%). They are tied under the rule, so 9.1 wins on false alarms. Both are in `compare_fuzzy_off.py` so this is reproducible.
- **Earlier rule, kept for reference:** `eval_judge/chosen_thresholds.json` (judge alone, 9.5) is "highest recall with at most 10% of normal prompts flagged". At 9.5 the combined rule catches 41.1% of attacks and flags 10.0% of normal training prompts; 9.1 deliberately gives up the 10% target on long JailbreakHub prompts.

## Evidence

| Check | Result |
|---|---|
| Training 700, patterns OR judge 9.1 (fixed cutoff) | 67.1% of attacks caught, 19.7% of normal flagged, accuracy 73.7% |
| `labeled_prompts_500` (short, AI-written) | 66.0% caught, 0% flagged |
| `stress_prompts` (30 attacks, 40 normal) | 12/30 caught, 5/40 flagged |
| Live path vs saved scores (`verify_live_detection.py`, 720 prompts) | 0 decision mismatches, max score difference 0.005 |
| Garak + PyRIT live session 2026-10-02 (before the encoding patterns), 5,113 interactions | 22.0% flagged; of 1,058 Garak-confirmed successful attacks, 304 (28.7%) not flagged, mostly `encoding` |
| Encoding patterns, independent holdout (`encoding_holdout_80.json`) | attacks 7/41 -> 28/41, hard negatives 0/40 -> 0/40; no change on any normal set (`encoding_rule_eval_output.txt`) |
| Locked 300, judge alone at 9.5 (run once by `judge_test_validate.py`) | 40.0% caught, 11.3% flagged, accuracy 64.3% |
| Locked 300, v5 38 patterns OR judge at 9.1 (`locked_300_combined.py`, saved scores, fuzzy off) | 100/150 caught (66.7%), 41/150 normal flagged (27.3%), accuracy 69.7%; reproduced from `judge_test_scores.jsonl` |

## Known gaps

- FR3 in the project document says detection covers input **and** output. The judge covers the input only; the output side is patterns plus the leak check. Judging responses was never evaluated.
- Encoding attacks with no decode-and-obey wording (bare "Decode: <base64>", spaced or leet text, non-English "translate and obey") are still missed: 13 of 41 on the holdout.
- JailbreakHub labels are unaudited; a rough, unaudited estimate is that about 10% of "normal" training prompts are really attacks, so the normal-prompt flag rate overstates real false alarms.
- No benign traffic has gone through the live testbed yet, so the live false-alarm share is still unmeasured.
