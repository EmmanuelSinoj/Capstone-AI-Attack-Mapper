import sqlite3
c = sqlite3.connect("alert_store/alerts.db")
print("total rows:", c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
print("flagged:", c.execute("SELECT COUNT(*) FROM alerts WHERE category IS NOT NULL").fetchone()[0])
for r in c.execute("SELECT id, source, category, detector, confidence FROM alerts ORDER BY id DESC LIMIT 10").fetchall():
    print(r)
