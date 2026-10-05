"""rounds.py -- round tokens and run ids (see detection/PLAN_run_probe_ids.md).

A ROUND is one test session: the attack run(s) (Garak, PyRIT) plus the benign replay that goes with them.
Round token  : <YYYYMMDD>_<DETECTION_VERSION>-<n>          e.g. 20261006_v6-1   (UTC date; n counts rounds that day)
Run id       : <tool>_<round token>                        e.g. garak_20261006_v6-1, pyrit_..., benign_...
Rules        : one run id per tool per round (a second Garak run needs a new round), and the report pairs runs by the
               shared round token. State lives in reports/rounds.json.
Used by garak_runner.py, pyrit_runner.py, benign_replay_runner.py, run_round.py."""
import datetime, json, pathlib, re

HERE = pathlib.Path(__file__).parent
STATE = HERE / "reports" / "rounds.json"


def detection_version() -> str:
    """Read DETECTION_VERSION from ../detection/__init__.py without importing the package (no torch needed)."""
    m = re.search(r'DETECTION_VERSION\s*=\s*"([^"]+)"', (HERE.parent / "detection" / "__init__.py").read_text(encoding="utf-8"))
    if not m:
        raise RuntimeError("DETECTION_VERSION not found in detection/__init__.py")
    return m.group(1)


def _load() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {"latest": None, "counts": {}, "used": []}


def _save(s: dict) -> None:
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2), encoding="utf-8")


def new_round() -> str:
    s = _load(); base = f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}_{detection_version()}"
    n = s["counts"].get(base, 0) + 1
    s["counts"][base] = n; s["latest"] = f"{base}-{n}"; _save(s)
    return s["latest"]


def current_round() -> str:
    """Latest round if it is from today's UTC date and version, else start a new one."""
    s = _load(); today = f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}_{detection_version()}"
    if s["latest"] and s["latest"].rsplit("-", 1)[0] == today:
        return s["latest"]
    return new_round()


def claim_run_id(tool: str, round_token: str) -> str:
    """Return <tool>_<round>, and refuse (SystemExit) if that tool already ran in this round."""
    rid = f"{tool}_{round_token}"
    s = _load()
    if rid in s["used"]:
        raise SystemExit(f"ERROR: {rid} was already used. Start a new round with --new-round (one run per tool per round).")
    s["used"].append(rid); _save(s)
    return rid
