"""One-off: relabel old live alerts category 'prompt_injection' -> 'B' (Emmanuel's A-E taxonomy). Safe to re-run.

Inside the testbed container (default path; SQLite writes over a Windows host mount can fail):
    docker compose exec testbed python3 /app/alert_store/migrate_category_b.py
On a plain checkout:
    python3 alert_store/migrate_category_b.py path/to/alerts.db
Makes a timestamped backup next to the database first (skip with --no-backup)."""
import datetime, shutil, sqlite3, sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
DB = args[0] if args else "/app/alert_store/alerts.db"
if "--no-backup" not in sys.argv:
    bak = f"{DB}.bak-pre-categoryB-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(DB, bak); print("backup:", bak)
c = sqlite3.connect(DB)
n = c.execute("UPDATE alerts SET category='B' WHERE category='prompt_injection'").rowcount
c.commit()
print("updated", n)
print(c.execute("SELECT category, COUNT(*) FROM alerts GROUP BY category").fetchall())
print("quick_check:", c.execute("PRAGMA quick_check").fetchone()[0])
