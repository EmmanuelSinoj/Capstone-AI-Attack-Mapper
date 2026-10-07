"""
AI Attack Mapper -- Testbed service (Live Attack Path).

A thin FastAPI wrapper around a self-hosted Ollama model: the
"protected application" that Garak and PyRIT attack (see
live_attack_path/attack_generation/), that Detection inspects at both
input and output (live_attack_path/detection/), and that Auto-Hardening
patches by appending a countermeasure clause to system_prompt.txt (not
yet built -- Classification and Defense track).

Detection runs as a FastAPI BackgroundTask *after* the response is
already on its way back to the caller, per NFR1 ("detection... shall
complete promptly enough to avoid materially delaying the testbed's
response"). A slow judge-model call therefore never adds latency to
/chat itself -- it only delays when that interaction's alert shows up
in the Alert Store, which nothing in the live request path waits on.
"""

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from detection.logger import log_interaction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("testbed")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
MODEL = os.environ.get("TESTBED_MODEL", "llama3:8b")
SYSTEM_PROMPT_PATH = Path(__file__).parent / "system_prompt.txt"
# Immutable, numbered copies of every system prompt that has ever been used: prompts/system_prompt_v<N>.txt (added 2026-10-04,
# see detection/PLAN_run_probe_ids.md item 12). system_prompt.txt stays the ACTIVE prompt (what /chat uses by default).
PROMPTS_DIR = Path(os.environ.get("PROMPTS_DIR", str(Path(__file__).parent / "prompts")))

app = FastAPI(title="AI Attack Mapper Testbed", version="0.2.0")


class ChatMessage(BaseModel):
    # "user" or "assistant" -- mirrors Ollama's own message role names,
    # deliberately not re-inventing a different vocabulary here.
    role: str
    content: str


class ChatRequest(BaseModel):
    prompt: str
    # Optional: set by Attack Generation callers (Garak/PyRIT) so a
    # given interaction's alert can later be traced back to the probe
    # that produced it. Left null for ordinary/manual traffic.
    probe_id: Optional[str] = None
    # Optional (added 2026-10-04): names the test run this interaction belongs to, e.g. "garak_20261006_v6-1"
    # (see detection/PLAN_run_probe_ids.md). Set by the attack and benign-replay runners; left null for manual traffic.
    run_id: Optional[str] = None
    # Optional (added 2026-10-04): answer with this stored system-prompt version instead of the active one (replay runner,
    # before/after hardening comparison). Must exist in prompts/; the version actually used is logged on the alert row.
    use_system_prompt_version: Optional[int] = None
    # Optional (added 2026-09-26): prior conversation turns, oldest
    # first, NOT including the current `prompt`. Lets a caller run a
    # multi-turn escalation (see attack_generation/campaign_runner.py
    # and the dashboard's Campaign Console) where each turn actually
    # sees what came before it, rather than every "turn" being an
    # isolated single-shot request that can't build on an established
    # frame. Left null/omitted, behavior is identical to before this
    # field existed -- single system + user message, no history.
    history: Optional[List[ChatMessage]] = None


class ChatResponse(BaseModel):
    response: str
    model: str
    system_prompt_version: int


_VER_RE = re.compile(r"#\s*version:\s*(\d+)")


def _split(text: str) -> tuple[str, int]:
    match = _VER_RE.search(text)
    version = int(match.group(1)) if match else 0
    body = re.sub(r"^#.*\n?", "", text, count=1).strip()
    return body, version


def _versions() -> dict[int, Path]:
    out: dict[int, Path] = {}
    if PROMPTS_DIR.is_dir():
        for f in PROMPTS_DIR.glob("system_prompt_v*.txt"):
            m = re.fullmatch(r"system_prompt_v(\d+)\.txt", f.name)
            if m: out[int(m.group(1))] = f
    return dict(sorted(out.items()))


def _bootstrap_active_version() -> None:
    """Make sure the ACTIVE prompt is stored as an immutable numbered copy (never overwrites an existing one)."""
    try:
        text = SYSTEM_PROMPT_PATH.read_text()
        _, v = _split(text)
        PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
        path = PROMPTS_DIR / f"system_prompt_v{v}.txt"
        if v > 0 and not path.exists():
            with open(path, "x") as fh: fh.write(text)
    except Exception:
        logger.exception("Could not store the active system prompt as a numbered version")


def _read_system_prompt(requested: Optional[int] = None) -> tuple[str, int]:
    """Read a system prompt and its version tag: the ACTIVE one by default, or stored version `requested`.

    The version line (`# version: N`) lets the Alert Store record which
    prompt revision produced a given interaction, so Auto-Hardening's
    before/after evaluation can tell exactly which patch was in effect.
    """
    if requested is None:
        return _split(SYSTEM_PROMPT_PATH.read_text())
    path = _versions().get(requested)
    if path is None:
        raise HTTPException(status_code=400, detail=f"system prompt version {requested} is not stored (have: {sorted(_versions())})")
    return _split(path.read_text())


def _log_interaction_safe(
    prompt: str,
    response: str,
    probe_id: Optional[str],
    version: int,
    system_prompt: Optional[str] = None,
    run_id: Optional[str] = None,
) -> None:
    """Wrap log_interaction so a detection-layer failure can never take
    down the testbed or surface as a 500 to the caller -- it only ever
    costs that one interaction's alert.

    `system_prompt` (added 2026-09-26) is the actual prompt text used
    for this request, forwarded through to the heuristic detector so it
    can confirm a genuine verbatim leak in the response -- see
    detection/heuristics.py for why this closes a real confidence-
    scoring gap (a leak used to score identically to a flat refusal)."""
    try:
        log_interaction(prompt, response, probe_id, version, system_prompt, run_id)
    except Exception:
        logger.exception("Detection/logging failed for this interaction (response was already sent).")


@app.get("/judge/health")
def judge_health(every: int = 250, force: bool = False):
    """Judge health for the round scripts (added 2026-10-05, fault fix): counters plus a canary pair (a known attack prompt
    must score >= the cutoff, a known benign one <= -5). Runs the canary if none has run yet, `every` judge calls have passed
    since the last one, or force=true. Not logged to the alert store. A sync function on purpose: it runs in the same thread
    pool as the background logging, i.e. under the same conditions as the real judge calls."""
    from detection import judge
    if force:
        judge.canary()
    return judge.health(canary_every=every)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "model": MODEL}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, background_tasks: BackgroundTasks):
    system_prompt, version = _read_system_prompt(req.use_system_prompt_version)

    messages = [{"role": "system", "content": system_prompt}]
    if req.history:
        messages.extend({"role": h.role, "content": h.content} for h in req.history)
    messages.append({"role": "user", "content": req.prompt})

    async with httpx.AsyncClient(timeout=180.0) as client:
        # 180s, not 60s: a model's *first* request after container start
        # (or after OLLAMA_KEEP_ALIVE idles it out) has to load several
        # GB of weights into VRAM before it can answer anything at all.
        # scripts/pull_models.ps1 warms every model during setup so this
        # timeout is a safety margin, not something normally exercised.
        r = await client.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": MODEL,
                "messages": messages,
                "stream": False,
            },
        )
        r.raise_for_status()
        data = r.json()

    response_text = data.get("message", {}).get("content", "")

    background_tasks.add_task(
        _log_interaction_safe, req.prompt, response_text, req.probe_id, version, system_prompt, req.run_id
    )

    return ChatResponse(
        response=response_text,
        model=MODEL,
        system_prompt_version=version,
    )


# ---------------------------------------------------------------------------
# System-prompt versions (item 12). Versions are append-only: a new prompt always becomes the next number and a stored
# number is never rewritten, so every alert row's system_prompt_version points at exactly one text forever.
# Auto-Hardening should use POST /prompts (+ activate) instead of editing system_prompt.txt in place.
# No authentication: the testbed is only reachable on the local compose network / localhost.
# ---------------------------------------------------------------------------
class NewPrompt(BaseModel):
    text: str
    activate: bool = False


class ActivatePrompt(BaseModel):
    version: int


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@app.get("/prompts")
async def list_prompts():
    _bootstrap_active_version()
    _, active = _split(SYSTEM_PROMPT_PATH.read_text())
    return {
        "active": active,
        "active_matches_stored": (_versions().get(active) is not None and _versions()[active].read_text() == SYSTEM_PROMPT_PATH.read_text()),
        "versions": [{"version": v, "sha256_16": _sha(p.read_text()), "chars": len(p.read_text())} for v, p in _versions().items()],
    }


@app.post("/prompts", status_code=201)
async def add_prompt(body: NewPrompt):
    text = re.sub(r"^#\s*version:.*\n?", "", body.text.strip() + "\n", count=1).strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty prompt")
    _bootstrap_active_version()
    PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
    n = max(_versions() or {0: None}) + 1
    full = f"# version: {n}\n{text}\n"
    with open(PROMPTS_DIR / f"system_prompt_v{n}.txt", "x") as fh:   # "x": refuse to overwrite
        fh.write(full)
    if body.activate:
        SYSTEM_PROMPT_PATH.write_text(full)
    return {"version": n, "active": bool(body.activate), "sha256_16": _sha(full)}


@app.post("/prompts/activate")
async def activate_prompt(body: ActivatePrompt):
    path = _versions().get(body.version)
    if path is None:
        raise HTTPException(status_code=400, detail=f"version {body.version} is not stored (have: {sorted(_versions())})")
    SYSTEM_PROMPT_PATH.write_text(path.read_text())
    return {"active": body.version}


@app.on_event("startup")
async def _startup() -> None:
    _bootstrap_active_version()
