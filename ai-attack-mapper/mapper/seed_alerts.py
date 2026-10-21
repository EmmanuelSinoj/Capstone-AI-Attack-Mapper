"""
mapper/seed_alerts.py

Demo-only. For real evaluation load Shadi's 40 synthetic alerts instead
(synthetic_alerts/load_alerts.py) and use pilot.py.

Loads the 4 hand-written test alerts (test_alerts.py) into the real
alert_store as UNCLASSIFIED rows (category=NULL) -- i.e. as if they'd come
in through the live testbed / synthetic generator and were waiting for the
Mapper to run on them.

Why this exists: neither Aneeq's testbed nor Shadi's synthetic batch has
landed real rows in alerts.db yet, so without this, the dashboard's
"Classify pending alerts" button has nothing to classify and every chart
is empty. This is dev/demo seed data only -- it inserts the ground_truth
columns too (ground_truth_category, from the documented expected response)
so the dashboard can show real accuracy numbers against something, but it
should not be run against a database that already has real pipeline data
in it without thinking about why (hence --force below).

Usage:
    python3 -m mapper.seed_alerts            # refuses if alerts.db has rows already
    python3 -m mapper.seed_alerts --force     # inserts anyway
"""

import argparse

# alert_store is a sibling top-level package, not a submodule of mapper --
# see pipeline.py's comment on the same import.
from alert_store import db as alert_db
from .test_alerts import TEST_ALERTS


def seed(conn=None, force: bool = False) -> int:
    owns_conn = conn is None
    if owns_conn:
        conn = alert_db.get_connection()

    try:
        existing = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if existing and not force:
            print(f"alerts.db already has {existing} row(s) -- not seeding. Pass --force to add anyway.")
            return 0

        inserted = 0
        for case in TEST_ALERTS:
            expected = case["expected_response"]
            alert_db.insert_alert(
                conn,
                source=case["source"],
                input=case["input"],
                output=case.get("output"),
                detector="seed:mapper.seed_alerts",
                # a seeded LIVE alert stands in for one the detector flagged ('B'), otherwise
                # db.get_mapper_queue() would (correctly) never send it to the Mapper
                category="B" if case["source"] == "live" else None,
                ground_truth_category=expected["category"],
            )
            inserted += 1
        print(f"Seeded {inserted} unclassified alert(s) from test_alerts.TEST_ALERTS.")
        return inserted
    finally:
        if owns_conn:
            conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Seed even if alerts.db already has rows.")
    args = parser.parse_args()
    seed(force=args.force)
