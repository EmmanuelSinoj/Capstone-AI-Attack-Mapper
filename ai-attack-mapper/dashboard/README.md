# Dashboard (Live Ops Console)

**Track:** Testbed and Detection (owner: Aneeq)

A read-only web UI over the Alert Store, Ollama, and the testbed, so a
garak/PyRIT run can be watched from a browser instead of tailed across
three terminal windows. Built after the first couple of real runs made
it clear that was the actual bottleneck to *watching* the pipeline, not
running it -- see PROGRESS_LOG.md's 2026-09-21 entry.

## What's here

- `app.py` -- FastAPI backend. Serves `/api/stats`, `/api/alerts/feed`,
  `/api/timeseries`, `/api/services`, `/api/runs`, and the static
  frontend. Every data source it touches is read-only (see the
  module's own docstring for exactly how alerts.db is opened).
- `static/index.html` -- the single-page frontend. Vanilla HTML/CSS/JS,
  no build step, no framework -- polls the API above every 2-6s and
  re-renders. Dark "ops console" styling (Orbitron/Share Tech Mono via
  Google Fonts, cyan/magenta/red accents, animated stat counters, a
  live scrolling interaction feed, VRAM bars, a throughput chart drawn
  on a plain `<canvas>`).
- `Dockerfile`, `requirements.txt` -- same pattern as
  `live_attack_path/testbed/`.

## Why a separate service instead of routes on testbed/app.py

Keeps the testbed's dependency footprint (torch, transformers -- see
`testbed/requirements.txt`) untouched by anything dashboard-only, and
means this can be rebuilt/restarted independently of the testbed while
an attack run is in flight, without interrupting it.

## Running it

Already wired into the root `docker-compose.yml` as the `dashboard`
service. From the project root:

```bash
docker compose up -d --build dashboard
```

Then open **http://localhost:8080** (or whatever `DASHBOARD_PORT` is
set to in `.env`). It'll come up even before `ollama`/`testbed` are
healthy -- it just shows them as offline until they are, which is
itself useful as a first thing to check.

## What it shows, and where each number comes from

- **Stat tiles** -- total/flagged/clean counts and flag rate, straight
  from `alerts.db` (`category IS NOT NULL` is the same "flagged"
  definition `detection/logger.py` itself uses -- see that file if this
  ever needs to change, since this dashboard just mirrors it, doesn't
  redefine it).
- **Judge status** -- ACTIVE vs. heuristics-only, read off whether any
  row's `detector` column shows a real judge verdict rather than the
  `judge:unavailable` fallback (see `detection/judge.py`). Will read
  "heuristics-only" until `HF_TOKEN` is set -- see the open items in
  PROGRESS_LOG.md.
- **Live interaction feed** -- polls for new alert rows and appends
  them with a flash animation (red flash for flagged, cyan for clean).
  This is the panel that replaces watching garak's own terminal output
  scroll by -- during a run, this fills in near real time because the
  testbed logs every `/chat` call regardless of caller (see the
  attack_generation README's "doesn't write to the Alert Store
  directly" section for why that's true regardless of which tool is
  generating the traffic).
- **Service status** -- Ollama via its own `/api/ps` (loaded model,
  VRAM residency %, same math the `ollama ps` CLI's PROCESSOR column
  does), testbed via its existing `/healthz`.
- **Throughput chart** -- alerts per minute, last 30 minutes, bucketed
  server-side in `/api/timeseries`.
- **Top detectors** -- which heuristic pattern (or judge label) is
  firing most often, among flagged rows only.
- **Recent runs** -- garak report files found in
  `attack_generation/reports/`, listing only (name/size/mtime) -- see
  `/api/runs`'s docstring in `app.py` for why it doesn't parse the
  report bodies on every poll.

## Known limitations / next step

- **No live run-triggering from the UI yet.** This first version is
  purely observational -- you still kick off `garak_runner.py` /
  `pyrit_runner.py` from a terminal, and watch the results land here.
  Launching a run from a button in the dashboard (streaming its stdout
  over a WebSocket into a live log panel) would be the natural next
  step if that's worth the added complexity of bundling garak/PyRIT
  (and their own dependencies) into this container too, or shelling
  out to the host -- neither is done here, flagged rather than
  silently skipped.
- **PyRIT traffic and synthetic alerts render the same as everything
  else** -- the feed doesn't yet distinguish *which* generator produced
  a given live-source row beyond the existing `probe_id` field (null
  for PyRIT traffic -- see attack_generation's own "Known limitation"
  section). Not a dashboard bug, just inherits that upstream gap.
- **Polling, not WebSockets.** Simpler to build and reason about, and
  at this traffic volume (thousands of rows per run, not millions per
  second) 2-second polling is indistinguishable from "live" to a human
  watching the screen. Worth revisiting only if that stops being true.
