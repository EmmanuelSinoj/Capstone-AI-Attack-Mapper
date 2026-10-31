#!/usr/bin/env python3
"""mark_hardened.py -- set alerts.hardening_applied for the alerts a cycle hardened against.

Called by run_cycle.py approve (value 1, only after the new version is active) and rollback (value 0).
It WRITES to the alert store, so it runs inside the testbed container (SQLite writes over the host mount fail):

  docker compose run --rm --no-deps -v <ai-attack-mapper>/orchestrator:/app/orchestrator:ro testbed \
      python3 /app/orchestrator/mark_hardened.py --db /app/alert_store/alerts.db --ids-file <file> --value 1
Stdlib only."""
import argparse, sqlite3, sys


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--ids-file", required=True, help="one alert id per line (gate.py rowid)")
    ap.add_argument("--value", type=int, choices=[0, 1], required=True)
    a = ap.parse_args()
    ids = [int(x) for x in open(a.ids_file, encoding="utf-8").read().split()]
    if not ids:
        print("no ids, nothing to do"); return 0
    con = sqlite3.connect(a.db)
    with con:
        n = 0
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            n += con.execute(f"UPDATE alerts SET hardening_applied = ? WHERE rowid IN ({','.join('?' * len(chunk))})", [a.value, *chunk]).rowcount
    con.close()
    print(f"hardening_applied = {a.value} on {n} of {len(ids)} alerts")
    return 0 if n == len(ids) else 1


if __name__ == "__main__":
    sys.exit(main())
