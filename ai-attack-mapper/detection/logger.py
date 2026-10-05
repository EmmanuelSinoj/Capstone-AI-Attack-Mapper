"""
Combines heuristic + judge-model verdicts into a single alert row and
writes it to the shared Alert Store. This is the "Detection & Alert
Logging" box in the architecture diagram -- called by the testbed's
/chat endpoint (as a background task, so detection latency never
delays the user-facing response; see NFR1) after every interaction.
"""

import logging
from typing import Optional

from alert_store.db import get_connection, insert_alert

from . import heuristics, judge

logger = logging.getLogger("detection.logger")

# Taxonomy code written to alerts.category when a detector fires. The Mapper's five-category taxonomy uses
# letter codes A-E; live prompt injection / jailbreaking is "B". The alert store rejects anything else on new
# databases (Emmanuel's PR #5), and this runs as a background task, so a wrong value would silently stop alerts
# being logged. Unflagged interactions keep category NULL.
CATEGORY_LIVE_PROMPT_INJECTION = "B"


def log_interaction(
    prompt: str,
    response: str,
    probe_id: Optional[str],
    system_prompt_version: int,
    system_prompt: Optional[str] = None,
    run_id: Optional[str] = None,
) -> dict:
    """Run detection on one interaction and write it to the Alert Store.

    Every interaction is logged (so the full traffic history is
    available for later analysis, e.g. the attack-success-rate replay
    in Evaluation), but `category` is only set when a detector fires --
    that's the signal the classification engine and Auto-Hardening act
    on. Returns the verdict dict, mainly so app.py can log it too.

    `system_prompt` (added 2026-09-26, optional/backward-compatible) is
    the actual current system prompt text, passed straight through to
    heuristics.check_interaction so it can confirm a genuine verbatim
    leak in the response rather than relying on regex phrasing alone --
    see heuristics.py's module docstring for the full rationale.
    """
    h_flagged, h_matches, h_confidence = heuristics.check_interaction(
        prompt, response, system_prompt
    )
    j_flagged, j_detail, j_confidence = judge.check_interaction(prompt, response)

    flagged = h_flagged or j_flagged
    confidence = max(h_confidence, j_confidence)

    detector_parts = []
    if h_matches:
        detector_parts.append(f"heuristic:{','.join(h_matches)}")
    else:
        detector_parts.append("heuristic:clean")
    detector_parts.append(
        "judge:unavailable" if j_detail == "judge_unavailable" else f"judge:{j_detail}"
    )
    detector = " | ".join(detector_parts)

    conn = get_connection()
    try:
        alert_id = insert_alert(
            conn,
            source="live",
            input=prompt,
            output=response,
            detector=detector,
            confidence=confidence,
            category=CATEGORY_LIVE_PROMPT_INJECTION if flagged else None,
            probe_id=probe_id,
            run_id=run_id,
            system_prompt_version=system_prompt_version,
        )
    finally:
        conn.close()

    verdict = {
        "alert_id": alert_id,
        "flagged": flagged,
        "confidence": confidence,
        "detector": detector,
    }
    if flagged:
        logger.warning("Flagged interaction -> alert #%s (%s)", alert_id, detector)
    else:
        logger.info("Interaction logged, not flagged -> alert #%s", alert_id)
    return verdict
