"""
mapper/pipeline.py

Production path: classify every alert still waiting for the Mapper and store
the answer on the alert row. (The model-selection pilot does NOT use this --
it stores every run separately in mapper_results; see pilot.py.)

Follows the shared alert store's contract (alert_store/README.md, v3):
  - which alerts are waiting: db.get_mapper_queue() -- every unclassified
    synthetic alert, and every unclassified LIVE alert the detector flagged
    (category set). Clean, unflagged live traffic is never sent to the Mapper.
  - what the Mapper may see: db.get_mapper_input() -- id, source, input,
    output only, so the answer key can't leak into the prompt.
  - where the answer goes: db.save_classification() -- predicted_category,
    classified_at, sub_cluster, framework ID lists (JSON), etc. The detector's
    own `category` flag and `confidence` are never touched.

An alert whose reply is unusable is left unclassified (classified_at stays
NULL) so the next run picks it up again; the error is returned to the caller.
"""

import time

from alert_store import db as alert_db

from . import classify


def classify_pending_alerts(conn=None, backend: str = "claude", limit: int | None = None,
                            retries: int = 1, **backend_kwargs) -> list[dict]:
    owns_conn = conn is None
    if owns_conn:
        conn = alert_db.get_connection()
    try:
        queue = alert_db.get_mapper_queue(conn, limit=limit)
        alerts = alert_db.get_mapper_input(conn, ids=queue) if queue else []
        results = []
        for alert in alerts:
            t0 = time.time()
            att = classify.classify_alert_full(
                alert["id"], alert["source"], alert["input"], alert["output"],
                backend=backend, retries=retries, **backend_kwargs,
            )
            outcome = {"alert_id": alert["id"], "source": alert["source"],
                       "elapsed_s": round(time.time() - t0, 2), "attempts": att.attempts}
            if att.ok:
                alert_db.save_classification(conn, alert["id"], att.parsed)
                outcome.update(status="ok", category=att.result.category,
                               severity=att.result.severity, confidence=att.result.confidence)
            else:
                snippet = (att.raw_text or "").strip().replace("\n", " ")[:300]
                outcome.update(status="error",
                               error=att.error + (f" -- raw model output: {snippet!r}" if snippet else ""))
            if att.meta.get("warning"):
                outcome["warning"] = att.meta["warning"]
            results.append(outcome)
        return results
    finally:
        if owns_conn:
            conn.close()
