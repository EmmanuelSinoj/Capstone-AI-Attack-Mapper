"""
Judge-model detector: a second-pass semantic check using Meta's
Prompt-Guard-86M, for interactions the heuristics don't already flag
(or to corroborate ones they do).

Two deliberate design choices, both worth knowing before touching this
file:

1. Prompt-Guard-86M, not Llama Guard 3 8B. The Design section allows
   either. Llama Guard 3 8B is already ~4.9GB in Ollama and would sit
   in VRAM *alongside* the ~4.7GB testbed model -- on an 8GB-class GPU
   (RTX 5060) that doesn't fit, so Ollama would evict and reload one of
   them on every other request. Prompt-Guard-86M avoids that problem by
   being tiny (86M params) rather than by avoiding the GPU.

2. GPU placement (changed 2026-09-29, was CPU-only): Prompt-Guard-86M's
   own footprint (weights + CUDA context) is small enough to fit in the
   RTX 5060's remaining VRAM headroom alongside llama3:8b -- observed
   6.6/8.1GB used under load, leaving enough room for an 86M-param
   model. `device=0` here assumes a single-GPU host with the same setup
   this was verified against; if VRAM ever gets tight (e.g. after
   raising OLLAMA_NUM_PARALLEL, or adding another GPU-resident model),
   check `nvidia-smi` headroom before assuming this still fits, and
   fall back to `device=-1` (CPU) if it doesn't -- that's a one-line
   change here, not a redesign, since `check()` below already degrades
   to heuristics-only on any load or inference failure.

3. Prompt-Guard-86M is a *gated* Hugging Face model -- accepting
   Meta's license on the model page and generating an access-approved
   token is required before it can be downloaded. Set HF_TOKEN in
   .env. If it's missing or not yet approved, this module logs a
   warning and reports "unavailable" rather than crashing the testbed
   or silently reporting everything as safe -- detection then falls
   back to heuristics-only, which is a visible degradation (check the
   testbed logs), not a silent one. The same applies to a GPU-kernel
   mismatch (torch too old for this GPU's compute capability) or any
   other inference-time failure, not just the load step -- see check()
   below.
"""

import logging
import math
import os
import threading
from typing import Optional, Tuple

logger = logging.getLogger("detection.judge")

_MODEL_NAME = "meta-llama/Prompt-Guard-86M"
# Prompt-Guard-86M's own max sequence length (mDeBERTa-v3-based). Passed
# explicitly because `truncation=True` alone is a no-op without it --
# transformers logs "Asking to truncate to max_length but no maximum
# length is provided" and then does NOT truncate, letting arbitrarily
# long input (e.g. garak's encoding.* probes, which generate long
# encoded/garbled strings) through uncapped. Discovered 2026-09-29 while
# investigating an unexplained testbed container restart during a garak
# run; not confirmed as the actual cause (no traceback was found either
# way), but it was a real latent gap worth closing regardless.
_MAX_LENGTH = 512
_pipeline = None
_load_lock = threading.Lock()
_load_attempted = False


def _get_pipeline():
    global _pipeline, _load_attempted

    if _pipeline is not None:
        return _pipeline

    # No unlocked "load already attempted" shortcut here: a request arriving while another thread is
    # still loading the model must WAIT on the lock for the result, not be told "unavailable"
    # (found 2026-10-02: the first PyRIT interactions after a restart were logged judge:unavailable).
    with _load_lock:
        if _pipeline is not None or _load_attempted:
            return _pipeline
        _load_attempted = True
        try:
            from transformers import pipeline  # heavy import, kept lazy on purpose

            token = os.environ.get("HF_TOKEN")
            _pipeline = pipeline(
                "text-classification",
                model=_MODEL_NAME,
                token=token,
                device=0,  # GPU -- see module docstring, point 2. Was -1 (CPU) before 2026-09-29.
            )
            logger.info("Loaded %s for judge-model detection (device=0/GPU).", _MODEL_NAME)
        except Exception as exc:  # noqa: BLE001 -- any load failure must degrade, never crash
            logger.warning(
                "Judge model unavailable (%s). Falling back to heuristics-only "
                "detection. If this is an auth/gated-access error, request access "
                "at huggingface.co/meta-llama/Prompt-Guard-86M and set HF_TOKEN in .env. "
                "If it's a CUDA/kernel error, the installed torch build may be too old "
                "for this GPU's compute capability -- see requirements.txt's comment.",
                exc,
            )
    return _pipeline


def check(text: str) -> Tuple[str, float]:
    """Classify a single piece of text.

    Returns (label, score). label is one of Prompt-Guard-86M's own
    labels ("BENIGN", "INJECTION", "JAILBREAK"), or "UNAVAILABLE" if
    the model couldn't be loaded OR if this specific inference call
    failed (e.g. a GPU kernel error on a particular input) -- the
    latter didn't used to be caught here at all (only the load step
    was guarded), so a single bad input could crash the process instead
    of degrading. Added 2026-09-29 alongside the GPU move, since a new
    class of inference-time failure (kernel/CUDA errors) became
    possible that couldn't happen on CPU.
    """
    if not text:
        return "BENIGN", 1.0

    clf = _get_pipeline()
    if clf is None:
        return "UNAVAILABLE", 0.0

    try:
        result = clf(text, truncation=True, max_length=_MAX_LENGTH)[0]
        return result["label"], float(result["score"])
    except Exception as exc:  # noqa: BLE001 -- inference failure must degrade, never crash
        logger.warning("Judge model inference failed on this interaction (%s). "
                        "Treating as unavailable for this interaction only -- the "
                        "loaded pipeline is left in place for the next call.", exc)
        return "UNAVAILABLE", 0.0


# --- Decision rule (changed 2026-10-02 to match the detection report) -----------------------
# The prompt is flagged when the judge's JAILBREAK log-odds,
#     lo_jailbreak = logit_JAILBREAK - logsumexp(logit_BENIGN, logit_INJECTION),
# reaches JUDGE_THRESHOLD. This is what was cross-validated on JailbreakHub (700 train / 300
# test); the old rule ("flag whenever the top label isn't BENIGN") was never evaluated.
# 9.1 = the cutoff the report states. Override with env JUDGE_THRESHOLD for experiments only.
# Only the PROMPT is judged: the response is not scored by the judge (the evaluation never
# covered responses, and response-side leaks are caught by heuristics._check_system_prompt_leak).
# Prompts longer than 512 tokens are scored in non-overlapping 510-token windows (max over windows).
JUDGE_THRESHOLD = float(os.environ.get("JUDGE_THRESHOLD", "9.1"))


def _lse(xs):
    m = max(xs)
    return m + math.log(sum(math.exp(x - m) for x in xs))


def score_prompt(text: str):
    """Return (lo_jailbreak, p_jailbreak), or None if the judge is unavailable / inference failed.

    Identical maths to eval_judge/judge_scoring.score_text (raw logits, float64, token-space
    windows), re-implemented here so the live path does not import the evaluation folder.
    """
    if not text:
        return float("-inf"), 0.0
    clf = _get_pipeline()
    if clf is None:
        return None
    try:
        import torch  # already a dependency of transformers; kept lazy like the pipeline import

        tok, model = clf.tokenizer, clf.model
        id2label = {int(k): v.upper() for k, v in model.config.id2label.items()}
        label2id = {v: k for k, v in id2label.items()}
        content = tok(text, add_special_tokens=False, truncation=False)["input_ids"]
        step = _MAX_LENGTH - 2
        wins = [content[s:s + step] for s in range(0, len(content), step)] or [[]]
        dev = next(model.parameters()).device
        best_lo, best_p = -1e9, 0.0
        for w in wins:
            ids = torch.tensor([[tok.cls_token_id] + w + [tok.sep_token_id]], device=dev)
            with torch.no_grad():
                lg = model(input_ids=ids, attention_mask=torch.ones_like(ids)).logits[0].double().cpu().tolist()
            lB, lI, lJ = (lg[label2id[k]] for k in ("BENIGN", "INJECTION", "JAILBREAK"))
            best_lo = max(best_lo, lJ - _lse([lB, lI]))
            best_p = max(best_p, math.exp(lJ - _lse([lB, lI, lJ])))
        return best_lo, best_p
    except Exception as exc:  # noqa: BLE001 -- inference failure must degrade, never crash
        logger.warning("Judge model inference failed on this interaction (%s). "
                       "Treating as unavailable for this interaction only.", exc)
        return None


def check_interaction(prompt: str, response: str) -> Tuple[bool, str, float]:
    """Judge the PROMPT only. Returns (flagged, detail, confidence).

    detail format (kept compatible with alert_store/check_garak_run.py's "clean" filter):
      "prompt=JAILBREAK(lo=10.25)"  flagged (log-odds >= JUDGE_THRESHOLD)
      "prompt=BENIGN(lo=3.10)"      not flagged ("BENIGN" here means "below threshold")
      "judge_unavailable"           model could not be loaded / inference failed
    `response` is accepted for API compatibility and is intentionally unused.
    """
    scored = score_prompt(prompt)
    if scored is None:
        return False, "judge_unavailable", 0.0
    lo, p_jb = scored
    if lo >= JUDGE_THRESHOLD:
        return True, f"prompt=JAILBREAK(lo={lo:.2f})", p_jb
    return False, f"prompt=BENIGN(lo={lo:.2f})", 0.0
