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
   them on every other request, which is slower than just running the
   much smaller (86M-parameter) Prompt-Guard model on CPU. This keeps
   the two GPU-resident models (testbed + whatever the classification
   pilot uses) from fighting the judge model for VRAM.

2. Prompt-Guard-86M is a *gated* Hugging Face model -- accepting
   Meta's license on the model page and generating an access-approved
   token is required before it can be downloaded. Set HF_TOKEN in
   .env. If it's missing or not yet approved, this module logs a
   warning and reports "unavailable" rather than crashing the testbed
   or silently reporting everything as safe -- detection then falls
   back to heuristics-only, which is a visible degradation (check the
   testbed logs), not a silent one.
"""

import logging
import os
import threading
from typing import Optional, Tuple

logger = logging.getLogger("detection.judge")

_MODEL_NAME = "meta-llama/Prompt-Guard-86M"
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
                device=-1,  # CPU -- see module docstring, point 1
            )
            logger.info("Loaded %s for judge-model detection.", _MODEL_NAME)
        except Exception as exc:  # noqa: BLE001 -- any load failure must degrade, never crash
            logger.warning(
                "Judge model unavailable (%s). Falling back to heuristics-only "
                "detection. If this is an auth/gated-access error, request access "
                "at huggingface.co/meta-llama/Prompt-Guard-86M and set HF_TOKEN in .env.",
                exc,
            )
    return _pipeline


def check(text: str) -> Tuple[str, float]:
    """Classify a single piece of text.

    Returns (label, score). label is one of Prompt-Guard-86M's own
    labels ("BENIGN", "INJECTION", "JAILBREAK"), or "UNAVAILABLE" if
    the model couldn't be loaded.
    """
    if not text:
        return "BENIGN", 1.0

    clf = _get_pipeline()
    if clf is None:
        return "UNAVAILABLE", 0.0

    result = clf(text, truncation=True)[0]
    return result["label"], float(result["score"])


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
