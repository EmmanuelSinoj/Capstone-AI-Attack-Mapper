"""
mapper/pipeline.py

Production path: classify every alert still waiting for the Mapper and store
the answer on the alert row. (The model-selection pilot does NOT use this --
it stores every run separately in mapper_results; see pilot.py.)

Follows the shared alert store's contract (alert_store/README.md, v3):
  - which alerts are waiting: db.get_mapper_queue() -- every unclassified
    synthetic alert, every unclassified LIVE alert the detector flagged
    (category set), and every unclassified live attack that worked
    (attack_succeeded = 1) even if the detector missed it. Other unflagged
    live traffic is never sent to the Mapper.
  - what the Mapper may see: db.get_mapper_input() -- id, source, input,
    output only, so the answer key can't leak into the prompt.
  - where the answer goes: db.save_classification() -- predicted_category,
    classified_at, sub_cluster, framework ID lists (JSON), etc. The detector's
    own `category` flag and `confidence` are never touched.

An alert whose reply is unusable is left unclassified (classified_at stays
NULL) so the next run picks it up again; the error is returned to the caller.
"""

import argparse
import os
import time

from alert_store import db as alert_db

from . import classify


def classify_pending_alerts(conn=None, backend: str = "claude", limit: int | None = None,
                            retries: int = 1, source: str | None = None, **backend_kwargs) -> list[dict]:
    owns_conn = conn is None
    if owns_conn:
        conn = alert_db.get_connection(os.environ.get("MAPPER_DB") or None)
    try:
        queue = alert_db.get_mapper_queue(conn, source=source, limit=limit)
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


def main(argv=None) -> None:
    """Classify waiting alerts and print one line per alert.
         py -m mapper.pipeline --source live            # flagged live alerts only
         py -m mapper.pipeline --source live --limit 5  # try a few first
       Uses alert_store/alerts.db, or the file in MAPPER_DB. Default model: Haiku 5.5."""
    ap = argparse.ArgumentParser(prog="mapper.pipeline")
    ap.add_argument("--source", choices=["live", "synthetic"], default=None,
                    help="only this source (default: both)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--backend", choices=["claude", "ollama"], default="claude")
    ap.add_argument("--model", default=None)
    a = ap.parse_args(argv)
    kwargs = {"model": a.model} if a.model else {}
    results = classify_pending_alerts(backend=a.backend, limit=a.limit, source=a.source, **kwargs)
    if not results:
        print("Nothing waiting: no unclassified alerts" + (f" from {a.source}" if a.source else "")
              + ". Live alerts only queue once the detector flags them or the attack is graded as successful.")
        return
    ok = 0
    for r in results:
        if r["status"] == "ok":
            ok += 1
            print(f"alert {r['alert_id']:>4} [{r['source']}]: {r['category']} "
                  f"sev={r['severity']} conf={r['confidence']} ({r['elapsed_s']}s)")
        else:
            print(f"alert {r['alert_id']:>4} [{r['source']}]: ERROR {r['error'][:200]}")
    print(f"\n{ok}/{len(results)} classified. Unclassified ones stay in the queue for the next run.")


if __name__ == "__main__":
    main()
