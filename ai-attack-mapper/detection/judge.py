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

    if _pipeline is not None or _load_attempted:
        return _pipeline

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


def check_interaction(prompt: str, response: str) -> Tuple[bool, str, float]:
    """Check both sides of an interaction. Returns (flagged, detail, confidence)."""
    prompt_label, prompt_score = check(prompt)
    response_label, response_score = check(response)

    if prompt_label == "UNAVAILABLE" or response_label == "UNAVAILABLE":
        return False, "judge_unavailable", 0.0

    flagged = prompt_label != "BENIGN" or response_label != "BENIGN"
    detail = f"prompt={prompt_label}({prompt_score:.2f}) response={response_label}({response_score:.2f})"
    confidence = max(
        prompt_score if prompt_label != "BENIGN" else 0.0,
        response_score if response_label != "BENIGN" else 0.0,
    )
    return flagged, detail, confidence
