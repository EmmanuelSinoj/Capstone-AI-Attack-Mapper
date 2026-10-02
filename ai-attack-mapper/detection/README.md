> **UPDATE 2026-10-02 -- live design now matches the detection report.** A prompt is flagged if it matches
> one of the 38 exact patterns (Emmanuel's v5 set, after normalisation and base64/hex/ROT13 decoding) OR the
> judge's JAILBREAK log-odds is >= `JUDGE_THRESHOLD` (default 9.1, env-overridable). Only the *prompt* is
> judged. The fuzzy matcher (`rebuff_heuristics.py`) is removed. Any older paragraph below that mentions
> fuzzy matching or "flag if the judge's top label is not BENIGN" describes the superseded design.
> Evidence: `eval_judge/compare_fuzzy_off_output.txt`; live-path check: `eval_judge/verify_live_detection.py`.

# Detection & Alert Logging (Live Attack Path)

**Track:** Testbed and Detection (owner: Aneeq, backup: Shadi)

Inspects both the input to and the output of every `testbed` interaction,
combining heuristic pattern rules with a judge model. Writes a
structured row into the shared Alert Store
(`alert_store/schema.sql`, `source='live'`) for every interaction --
flagged or not -- so the full traffic history is available later
(e.g. for the attack-success-rate replay in Evaluation).

## What's here

- `heuristics.py` -- fast, synchronous pattern/keyword rules for known
  prompt-injection phrasing (instruction override, persona jailbreaks,
  prompt exfiltration attempts, filter-bypass requests). Cheap enough to
  run on every request; see the module for the current pattern list.
  As of 2026-09-25 also runs a fuzzy-matching second signal on the
  prompt (`rebuff_heuristics.py`) to catch paraphrased injection
  attempts the exact regex patterns miss -- see that file's docstring
  for provenance and `heuristics.py`'s own comments for how the two
  signals combine.
- `rebuff_heuristics.py` -- fuzzy-matching heuristic reused (Apache-2.0,
  with attribution) from the archived Rebuff project, via a teammate's
  independent reuse of the same file. Zero external dependencies. See
  PROGRESS_LOG.md's 2026-09-25 entry for why this one piece was worth
  adopting from a separately-built heuristic scanner while the rest of
  that implementation (LLM Guard wrapper, output-side refusal-absence
  check) wasn't -- at least not without side-by-side testing first.
- `judge.py` -- second-pass semantic check using **Prompt-Guard-86M**
  (not Llama Guard 3 8B -- see the module docstring for why: VRAM
  budget on the RTX 5060, and Prompt-Guard is small enough to run on
  CPU without needing the GPU at all). Requires an approved `HF_TOKEN`
  (Prompt-Guard-86M is gated on Hugging Face); degrades to
  heuristics-only detection with a logged warning if unavailable,
  rather than failing closed or silently reporting everything as safe.
- `logger.py` -- combines both verdicts and writes the alert via
  `alert_store/db.py`. This is what `testbed/app.py` actually calls,
  as a background task, after every `/chat` request.

## Design notes

Detection runs at **both** the input to and the output of the testbed
(see Design section, "LLM and GenAI Application Attacks" literature
finding: an attack's consequence is often realized after the initial
prompt, not within it) -- both `heuristics.check_interaction` and
`judge.check_interaction` take `(prompt, response)`, not just one side.

Detection runs as a FastAPI `BackgroundTask`, *after* the response is
already returned to the caller (see NFR1: detection must not
materially delay the testbed's response). This means a slow or
unavailable judge model never adds latency to `/chat` itself -- worst
case, that interaction's alert is a little late, or heuristics-only.

## Known limitation

Prompt-Guard-86M being gated means the judge model won't load at all
until someone on the team requests access at
huggingface.co/meta-llama/Prompt-Guard-86M and puts an approved token
in `.env` as `HF_TOKEN`. Until then, every alert's `detector` field will
read `judge:unavailable` and detection is heuristics-only -- check the
testbed's logs (`docker logs aam-testbed`) to confirm which mode you're
actually running in before trusting confidence scores.
