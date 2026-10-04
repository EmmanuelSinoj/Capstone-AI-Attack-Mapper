# Detection & Alert Logging (Live Attack Path)

**Track:** Testbed and Detection (owner: Aneeq, backup: Shadi) · **Version:** v6 (see `VERSION.md`)

Every `testbed` interaction is checked and written to the shared Alert Store (`alert_store/schema.sql`, `source='live'`), flagged or not, so the full traffic history is available later (for example for the attack-success-rate replay in Evaluation). A flagged interaction gets `category = "B"` (live prompt injection in the Mapper's A-E taxonomy); unflagged rows keep `category` NULL.

## The rule (v6)

A prompt is flagged if it matches one of the **43 exact patterns** (after normalisation and base64/hex/ROT13 decoding) **or** the Prompt-Guard-86M **JAILBREAK log-odds is at least 9.1**. The judge scores the **prompt only**; responses are covered by the patterns and by the system-prompt-leak check. The fuzzy matcher is gone. `VERSION.md` has the evidence, how 9.1 was chosen, and the known gaps.

## What's here

- `heuristics.py`: the exact patterns (v5's 38 plus 5 `encoding_smuggling`), `check()`, `check_interaction()` and the system-prompt-leak check (`_check_system_prompt_leak`: does the reply contain the real system prompt verbatim).
- `preprocessing.py`: Unicode and zero-width clean-up, homoglyph canonicalisation, base64/hex/ROT13 decode candidates.
- `judge.py`: Prompt-Guard-86M (not Llama Guard 3 8B: VRAM budget on the RTX 5060; it runs on the GPU, `device=0`). `score_prompt()` returns the JAILBREAK log-odds; `check_interaction()` applies `JUDGE_THRESHOLD` (default 9.1, env-overridable). Needs an approved `HF_TOKEN` (the model is gated). If the model cannot load or inference fails, the interaction is logged as `judge:unavailable` and detection falls back to patterns only; check `docker logs aam-testbed`. Requests that arrive while the model is still loading wait for it instead of being logged as unavailable.
- `logger.py`: combines both verdicts and writes the alert via `alert_store/db.py`. `testbed/app.py` calls it as a background task after every `/chat` response, so detection never delays the response (NFR1).
- `reporting/`: `detection_report.py` builds an HTML report of the latest attack session (Garak and PyRIT aware); `--round <token>` reports on one round instead: successful Garak/PyRIT attacks flagged by v6, benign-run flag rate with a confidence interval, and warnings for an incomplete round; `rescore_judge.py` scores older prompts with the live judge.
- `eval_judge/`: the evaluation scripts, saved scores and results (see its `README.md`).
- `VERSION.md`: what v6 contains and why.

## The detector column

`heuristic:<pattern names or clean> | judge:prompt=JAILBREAK(lo=9.44)` (flagged by the judge), `judge:prompt=BENIGN(lo=3.10)` (below the cutoff), or `judge:unavailable`. Rows logged before v6 use an older format (`prompt=INJECTION(1.00) response=...`, `rebuff_fuzzy(...)`) from the earlier design.

## Known limitations

- The judge is prompt-only, while FR3 in the project document says detection covers input and output; see `VERSION.md`.
- Prompt-Guard-86M is gated: until an approved token is in `.env` as `HF_TOKEN`, every row reads `judge:unavailable` and detection is patterns-only.
- Detection of novel attack wording degrades; the literature review's own warning applies here too.
