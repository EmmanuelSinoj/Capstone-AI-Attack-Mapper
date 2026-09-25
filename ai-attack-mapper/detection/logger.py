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


def log_interaction(
    prompt: str,
    response: str,
    probe_id: Optional[str],
    system_prompt_version: int,
) -> dict:
    """Run detection on one interaction and write it to the Alert Store.

    Every interaction is logged (so the full traffic history is
    available for later analysis, e.g. the attack-success-rate replay
    in Evaluation), but `category` is only set when a detector fires --
    that's the signal the classification engine and Auto-Hardening act
    on. Returns the verdict dict, mainly so app.py can log it too.
    """
    h_flagged, h_matches, h_confidence = heuristics.check_interaction(prompt, response)
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
            category="prompt_injection" if flagged else None,
            probe_id=probe_id,
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
