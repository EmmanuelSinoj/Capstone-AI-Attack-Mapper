"""judge_guard.py -- stop a test round the moment the testbed's judge stops working.  Standard library only.

Background (2026-10-05): round 20261005_v6-2 ran for ~3 hours with a judge that returned its failure value for every call;
nothing noticed. The testbed now has GET /judge/health (detection.judge.health): counters (non-finite logits, inference
errors, unavailable calls) plus a canary pair -- a known attack prompt must still score >= 9.1 and a known benign prompt <= -5.
The canary re-runs automatically once at least 250 judge calls have happened since the last one.

  preflight(base)        -> raises JudgeProblem unless the judge is healthy (forces a fresh canary). Call BEFORE starting a round.
  Watcher(base)          -> a thread that polls /judge/health while a round runs; .tripped says why it stopped. Use as
                            `with Watcher(base, on_trip=kill_fn): ...`.
  mark_invalid(round, why) is in rounds.py; run_round.py calls it when the guard trips.
"""
import json, threading, time, urllib.request

BASE = "http://localhost:8000"


class JudgeProblem(RuntimeError):
    pass


def fetch(base=BASE, force=False, every=250, timeout=60):
    url = f"{base}/judge/health?every={every}" + ("&force=true" if force else "")
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def describe(h):
    c = h.get("last_canary") or {}
    return (f"ok={h.get('ok')} device={h.get('device')} calls={h.get('calls')} nonfinite={h.get('nonfinite')} "
            f"inference_errors={h.get('inference_errors')} unavailable={h.get('unavailable')} "
            f"canary(attack={c.get('attack_lo')}, benign={c.get('benign_lo')}, ok={c.get('ok')}, runs={h.get('canary_runs')})")


def preflight(base=BASE):
    try:
        h = fetch(base, force=True)
    except Exception as e:  # noqa: BLE001
        raise JudgeProblem(f"cannot read {base}/judge/health ({e!r}). The testbed must be rebuilt/restarted with the 2026-10-05 fault fix (app.py + detection/judge.py).")
    if not h.get("ok"):
        raise JudgeProblem("judge is NOT healthy before the round: " + describe(h) + "  -> restart the testbed (docker compose restart testbed) and try again.")
    return h


class Watcher(threading.Thread):
    """Polls /judge/health every `interval` seconds. Trips on: unhealthy answer, or `max_unreachable` failed polls in a row."""
    def __init__(self, base=BASE, interval=20, max_unreachable=6, on_trip=None, every=250):
        super().__init__(daemon=True)
        self.base, self.interval, self.max_unreachable, self.on_trip, self.every = base, interval, max_unreachable, on_trip, every
        self.tripped = None; self.last = None; self.polls = 0; self._halt = threading.Event()

    def run(self):
        misses = 0
        while not self._halt.wait(self.interval):
            try:
                h = fetch(self.base, every=self.every); self.last = h; self.polls += 1; misses = 0
            except Exception as e:  # noqa: BLE001
                misses += 1
                if misses >= self.max_unreachable:
                    self._trip(f"/judge/health unreachable {misses} times in a row ({e!r})")
                continue
            if not h.get("ok"):
                self._trip("judge health failed: " + describe(h)); return

    def _trip(self, why):
        if self.tripped: return
        self.tripped = why
        print(f"\n!!! JUDGE GUARD TRIPPED: {why}\n!!! Stopping the round; its judge-based numbers would be invalid.", flush=True)
        if self.on_trip:
            try: self.on_trip()
            except Exception as e: print("   (on_trip failed:", e, ")")

    def stop(self): self._halt.set()
