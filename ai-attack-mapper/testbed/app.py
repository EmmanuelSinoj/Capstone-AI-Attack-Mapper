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

import logging
import os
import re
from pathlib import Path
from typing import Optional

import httpx
from fastapi import BackgroundTasks, FastAPI
from pydantic import BaseModel

from detection.logger import log_interaction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("testbed")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
MODEL = os.environ.get("TESTBED_MODEL", "llama3:8b")
SYSTEM_PROMPT_PATH = Path(__file__).parent / "system_prompt.txt"

app = FastAPI(title="AI Attack Mapper Testbed", version="0.2.0")


class ChatRequest(BaseModel):
    prompt: str
    # Optional: set by Attack Generation callers (Garak/PyRIT) so a
    # given interaction's alert can later be traced back to the probe
    # that produced it. Left null for ordinary/manual traffic.
    probe_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    model: str
    system_prompt_version: int


def _read_system_prompt() -> tuple[str, int]:
    """Read the current system prompt and its version tag.

    The version line (`# version: N`) lets the Alert Store record which
    prompt revision produced a given interaction, so Auto-Hardening's
    before/after evaluation can tell exactly which patch was in effect.
    """
    text = SYSTEM_PROMPT_PATH.read_text()
    match = re.search(r"#\s*version:\s*(\d+)", text)
    version = int(match.group(1)) if match else 0
    body = re.sub(r"^#.*\n?", "", text, count=1).strip()
    return body, version


def _log_interaction_safe(prompt: str, response: str, probe_id: Optional[str], version: int) -> None:
    """Wrap log_interaction so a detection-layer failure can never take
    down the testbed or surface as a 500 to the caller -- it only ever
    costs that one interaction's alert."""
    try:
        log_interaction(prompt, response, probe_id, version)
    except Exception:
        logger.exception("Detection/logging failed for this interaction (response was already sent).")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "model": MODEL}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, background_tasks: BackgroundTasks):
    system_prompt, version = _read_system_prompt()

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
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": req.prompt},
                ],
                "stream": False,
            },
        )
        r.raise_for_status()
        data = r.json()

    response_text = data.get("message", {}).get("content", "")

    background_tasks.add_task(
        _log_interaction_safe, req.prompt, response_text, req.probe_id, version
    )

    return ChatResponse(
        response=response_text,
        model=MODEL,
        system_prompt_version=version,
    )
