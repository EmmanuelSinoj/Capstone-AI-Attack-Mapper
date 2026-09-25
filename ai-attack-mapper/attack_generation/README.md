# Attack Generation (Live Attack Path)

**Track:** Testbed and Detection (owner: Aneeq, backup: Shadi)

Generates known and adaptive prompt-injection / jailbreak payloads
against the `testbed` service using Garak and PyRIT.

## What's here

- `garak_config.json` -- Garak REST generator config pointed at the
  testbed's `/chat` endpoint (schema per
  [garak's rest generator docs](https://reference.garak.ai/en/latest/garak.generators.rest.html)).
- `garak_runner.py` -- runs a chosen probe set against the testbed and
  writes garak's own report to `reports/` (kept for reference; **not**
  what populates the Alert Store -- see the script's docstring for why).
  Runs with tuned (fast) settings by default -- pass `--no-fast` for
  garak's slower, more exhaustive stock behavior.
- `garak_perf.yaml` -- runtime-tuning config (generations per prompt,
  soft prompt cap, client-side parallelism), added after the first real
  run against the live testbed projected to take multiple hours on a
  single local GPU. See its header comment for the exact numbers, the
  garak docs they're verified against, and how they're matched to
  `OLLAMA_NUM_PARALLEL` in the root `docker-compose.yml`.
- `pyrit_runner.py` -- orchestrates PyRIT attacks against the same
  endpoint via a custom `HTTPTarget`, for adaptive/objective-driven
  traffic rather than a fixed probe library.
- `requirements.txt` -- `garak`, `pyrit`.

## Important: this doesn't write to the Alert Store directly

Both tools just generate traffic and send it to `http://localhost:8000/chat`.
The **testbed itself** (`live_attack_path/testbed/app.py`) is what runs
detection and writes to `alert_store/alerts.db`, on every request
regardless of which tool -- or a human -- sent it. That's a deliberate
architectural choice: it means Garak's built-in detectors and PyRIT's
own scoring are irrelevant to whether an alert gets created; only this
project's own heuristics + judge model (`live_attack_path/detection/`)
decide that. Garak and PyRIT's only job is to be a good, varied source
of attack payloads.

## Setup

```bash
cd live_attack_path/attack_generation
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

Bring the stack up first (`docker compose ps` should show `ollama` and
`testbed` both healthy), then:

```bash
python garak_runner.py --probes promptinject,dan,encoding
python pyrit_runner.py
```

Check `alert_store/alerts.db` afterward (any SQLite browser, or
`alert_store/db.py`) to see what got logged.

## Performance: confirming GPU use, and why the default run is now faster

Before assuming the GPU is the bottleneck (or isn't), confirm Ollama is
actually serving `llama3:8b` on the GPU and not silently falling back
to CPU:

```bash
docker exec aam-ollama ollama ps      # PROCESSOR column should read "100% GPU"
docker exec aam-ollama nvidia-smi     # should list an ollama process using VRAM
```

If either shows CPU instead, the GPU reservation in `docker-compose.yml`
isn't taking effect (check Docker Desktop's Settings > Resources >
"Use NVIDIA GPU" is on, and that `docker compose up -d --force-recreate
ollama` was run after any compose-file change -- environment variable
edits don't take effect on a plain restart, the container has to be
recreated).

Assuming the GPU is confirmed, the actual time sink in the first real
run (2026-09-18) was garak's own stock defaults, not the GPU: 5
generations per prompt, no prompt cap, and fully serial requests. That
run was killed by Aneeq after 25+ minutes with 15+ probes still queued.
`garak_runner.py` now loads `garak_perf.yaml` by default, which cuts
generations to 2, caps prompts per probe at 128, and allows 2 requests
in flight at once (matched to `OLLAMA_NUM_PARALLEL=2` in
`docker-compose.yml` -- see both files' comments for the exact
reasoning and the garak docs consulted). Use `--no-fast` to fall back
to garak's slower, more exhaustive stock behavior once these scripts
are being used to produce final numbers rather than to iterate.

## Known limitation / next step

`probe_id` on logged alerts will be `null` for traffic sent through
Garak, since garak's REST generator doesn't expose per-request probe
metadata to the generator config -- there's no way to inject "this
request came from probe X" into the HTTP call itself. PyRIT's traffic
similarly has no probe_id (it's objective-driven, not probe-driven).
This doesn't block detection or classification (which reason over the
interaction content, not its source label), but it does mean you can't
yet ask "which garak probe produced this alert" directly from the
database. If that attribution turns out to matter for the Evaluation
section, the fix is a post-run correlation script that matches garak's
own report (which does have probe+prompt pairs) back to alert rows by
exact input text -- not yet built, flagged here rather than silently
skipped.
