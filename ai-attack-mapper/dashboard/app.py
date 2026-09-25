"""
AI Attack Mapper -- Live Ops Dashboard (Live Attack Path).

A read-only visualization layer over the Alert Store, Ollama, and the
testbed -- built so a garak/PyRIT run can be watched from a browser
instead of tailed across three different terminal windows (see
PROGRESS_LOG.md, 2026-09-21 entry, for why this got built and what it
replaces). This service never writes to alerts.db and never calls
/chat itself; it only polls existing endpoints/files and serves a
static single-page frontend that itself polls this API every few
seconds.

Why a separate service instead of adding routes to testbed/app.py:
keeps the testbed's own dependency footprint (torch, transformers --
see testbed/requirements.txt) untouched by anything dashboard-only,
and means the dashboard can be rebuilt/bounced independently while
attacks are in flight against the testbed without interrupting them.

Data sources, all read-only:
  - alert_store/alerts.db  -- bind-mounted read-only (see
    docker-compose.yml's `:ro` suffix on this service's volume) AND
    opened here via a `file:...?mode=ro` URI as a second, redundant
    safety net -- this process should never be able to write a row
    even if someone drops the `:ro` from the compose file later.
  - Ollama's own HTTP API (`/api/ps`) -- avoids needing the `ollama`
    CLI or a docker socket mount just to answer "is the model on the
    GPU"; `/api/ps` already reports size_vram vs size per loaded
    model, which is the same math `ollama ps`'s PROCESSOR column does.
  - testbed's existing `/healthz` endpoint.
  - attack_generation/reports/ -- bind-mounted read-only, listing only
    (see /api/runs below for why report bodies aren't parsed here).
"""

import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
TESTBED_HOST = os.environ.get("TESTBED_HOST", "http://testbed:8000")
DB_PATH = Path(os.environ.get("ALERTS_DB_PATH", "/app/alert_store/alerts.db"))
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/app/reports"))

app = FastAPI(title="AI Attack Mapper -- Live Ops Dashboard", version="0.1.0")


def _read_only_connection() -> Optional[sqlite3.Connection]:
    """Open alerts.db strictly read-only. Returns None if the db
    doesn't exist yet (e.g. before the stack has logged its first
    interaction) so callers can return sensible zeroed-out responses
    instead of a 500 on a fresh checkout."""
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/stats")
async def stats():
    conn = _read_only_connection()
    if conn is None:
        return {
            "total": 0, "flagged": 0, "clean": 0, "flag_rate": 0.0,
            "by_source": {}, "judge_active": False, "rate_per_min": 0.0,
            "top_detectors": [],
        }
    try:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        # "flagged" mirrors detection/logger.py's own definition: a row
        # only gets category="prompt_injection" when heuristics and/or
        # the judge model actually fired on it.
        flagged = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE category IS NOT NULL"
        ).fetchone()[0]

        by_source = {
            r["source"]: r["n"]
            for r in conn.execute(
                "SELECT source, COUNT(*) as n FROM alerts GROUP BY source"
            ).fetchall()
        }

        # Judge is "active" if any row's detector string shows a real
        # verdict rather than the unavailable fallback -- see
        # detection/judge.py / logger.py for the exact "judge:..."
        # string format this matches against.
        judge_active = bool(
            conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector LIKE '%judge:%' "
                "AND detector NOT LIKE '%judge:unavailable%'"
            ).fetchone()[0]
        )

        # Recent throughput, measured against the newest row's own
        # timestamp rather than wall-clock "now" -- avoids clock-skew
        # weirdness between this container and wherever alerts were
        # actually written, and reads as a clean 0 (not a stale
        # nonzero number) once the stack has gone idle after a run.
        newest = conn.execute(
            "SELECT timestamp FROM alerts ORDER BY id DESC LIMIT 1"
        ).fetchone()
        rate_per_min = 0.0
        if newest is not None:
            recent = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime(?, '-5 minutes')",
                (newest["timestamp"],),
            ).fetchone()[0]
            rate_per_min = round(recent / 5.0, 1)

        top_detectors = [
            {"detector": r["detector"], "count": r["n"]}
            for r in conn.execute(
                "SELECT detector, COUNT(*) as n FROM alerts WHERE category IS NOT NULL "
                "GROUP BY detector ORDER BY n DESC LIMIT 6"
            ).fetchall()
        ]

        return {
            "total": total,
            "flagged": flagged,
            "clean": total - flagged,
            "flag_rate": round(100 * flagged / total, 1) if total else 0.0,
            "by_source": by_source,
            "judge_active": judge_active,
            "rate_per_min": rate_per_min,
            "top_detectors": top_detectors,
        }
    finally:
        conn.close()


@app.get("/api/alerts/feed")
async def alerts_feed(since_id: int = Query(0), limit: int = Query(50, le=200)):
    """since_id=0 -> newest page (initial load, oldest-first for
    display). since_id=N -> everything newer than N, ascending -- the
    frontend polls this so it only ever pulls new rows to append to
    the live feed rather than re-fetching what's already on screen."""
    conn = _read_only_connection()
    if conn is None:
        return {"rows": [], "max_id": 0}
    try:
        cols = (
            "id, timestamp, source, category, detector, confidence, probe_id, "
            "substr(input, 1, 220) as input, substr(output, 1, 220) as output"
        )
        if since_id:
            rows = conn.execute(
                f"SELECT {cols} FROM alerts WHERE id > ? ORDER BY id ASC LIMIT ?",
                (since_id, limit),
            ).fetchall()
        else:
            rows = list(reversed(conn.execute(
                f"SELECT {cols} FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()))

        max_id = conn.execute("SELECT MAX(id) as m FROM alerts").fetchone()["m"] or 0

        return {
            "rows": [
                {
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "source": r["source"],
                    "flagged": r["category"] is not None,
                    "category": r["category"],
                    "detector": r["detector"],
                    "confidence": r["confidence"],
                    "probe_id": r["probe_id"],
                    "input": r["input"],
                    "output": r["output"],
                }
                for r in rows
            ],
            "max_id": max_id,
        }
    finally:
        conn.close()


@app.get("/api/timeseries")
async def timeseries(minutes: int = Query(30, le=180)):
    """Per-minute total/flagged counts for the throughput chart.
    Buckets by string-prefix slicing rather than parsing timestamps --
    alerts.db stores them as strftime('%Y-%m-%dT%H:%M:%fZ'), so the
    first 16 characters ("YYYY-MM-DDTHH:MM") already are the minute
    bucket key."""
    conn = _read_only_connection()
    if conn is None:
        return {"buckets": []}
    try:
        newest = conn.execute(
            "SELECT timestamp FROM alerts ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if newest is None:
            return {"buckets": []}

        rows = conn.execute(
            "SELECT timestamp, category FROM alerts WHERE timestamp >= datetime(?, ?) "
            "ORDER BY id ASC",
            (newest["timestamp"], f"-{minutes} minutes"),
        ).fetchall()

        buckets: dict[str, dict[str, int]] = {}
        for r in rows:
            key = r["timestamp"][:16]
            b = buckets.setdefault(key, {"total": 0, "flagged": 0})
            b["total"] += 1
            if r["category"] is not None:
                b["flagged"] += 1

        return {"buckets": [{"minute": k, **v} for k, v in sorted(buckets.items())]}
    finally:
        conn.close()


async def _probe_json(url: str, timeout: float = 3.0):
    """GET a JSON endpoint without ever raising -- a down service is a
    normal state for this dashboard to display, not an error to crash
    a request over."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            r.raise_for_status()
            return True, r.json(), None
    except Exception as exc:  # noqa: BLE001 -- surfaced to the UI as a status string
        return False, None, str(exc)


@app.get("/api/services")
async def services():
    testbed_ok, testbed_data, testbed_err = await _probe_json(f"{TESTBED_HOST}/healthz")
    ollama_ok, ollama_ps, ollama_err = await _probe_json(f"{OLLAMA_HOST}/api/ps")

    models = []
    if ollama_ok and ollama_ps:
        for m in ollama_ps.get("models", []):
            size = m.get("size") or 0
            size_vram = m.get("size_vram") or 0
            # Same ratio the `ollama ps` CLI's PROCESSOR column derives
            # from these same two fields -- 100% means fully GPU-resident.
            pct_gpu = round(100 * size_vram / size, 1) if size else 0.0
            models.append({
                "name": m.get("name"),
                "size_gb": round(size / (1024 ** 3), 2),
                "vram_gb": round(size_vram / (1024 ** 3), 2),
                "pct_gpu": pct_gpu,
                "expires_at": m.get("expires_at"),
            })

    return {
        "ollama": {"ok": ollama_ok, "models": models, "error": ollama_err},
        "testbed": {"ok": testbed_ok, "detail": testbed_data, "error": testbed_err},
    }


@app.get("/api/runs")
async def runs():
    """Recent garak report files -- listing only (name/size/mtime).
    Deliberately doesn't parse report.jsonl bodies here: some of these
    run 20MB+ (see garak_perf.yaml's header comment on run sizes), and
    re-parsing one on every ~5s poll would be real, pointless CPU/IO
    load for a dashboard. The one-off eval-summary parse used for
    PROGRESS_LOG.md's attack-success breakdown stays a separate,
    manually-run script rather than something this endpoint repeats
    continuously."""
    if not REPORTS_DIR.exists():
        return {"runs": []}
    files = sorted(
        REPORTS_DIR.glob("garak_run_*.report.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:10]
    return {
        "runs": [
            {
                "name": f.name,
                "size_mb": round(f.stat().st_size / (1024 ** 2), 2),
                "modified": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(f.stat().st_mtime)),
            }
            for f in files
        ]
    }


# Mounted last so every /api/* route above wins its match first --
# Starlette matches routes in registration order, and StaticFiles at
# "/" would otherwise swallow everything under it.
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
