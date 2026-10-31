"""
mapper/client.py

Thin wrapper around the two LLM backends the Model Selection Pilot compares
(local Ollama, Claude via the Anthropic Messages API). Only depends on
`requests`.

Settings come from the environment, and from the repo-root .env if one
exists (read once, never overriding a variable that is already set):
  CLASSIFIER_MODEL   Ollama model for the Mapper (default llama3:8b, as in .env.example)
  OLLAMA_HOST        default http://localhost:11434
  ANTHROPIC_API_KEY  needed for the Claude backend
  OLLAMA_NUM_CTX     context window to request (default 12288)

Two settings are fixed on purpose for the pilot:
  - temperature 0 on both backends, so a re-run of the same prompt gives (as
    near as the backend allows) the same answer, and dev-set changes reflect
    prompt changes rather than sampling noise. Claude is still not fully
    deterministic, which is why pilot.py supports repeats.
  - num_ctx 12288 on Ollama. The system prompt (v4, with the ATLAS catalog) is ~6,000 tokens; older
    Ollama versions default to a 2,048-token window and silently drop the
    start of anything longer, i.e. the taxonomy rules.

call_*_meta() return (text, meta) with token counts and latency, for
alert_store.db.save_mapper_result(). call_claude()/call_ollama() keep their
old signature (text only) for existing callers.
"""

import json
import os
import re
import threading
import time
from pathlib import Path

import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
# Production model, chosen in the Model Selection Pilot (Oct 21, 2026): Haiku 5.5 tied Sonnet 5.5
# on dev (100% category, consistency 1.0) and on held-out (91.7%, Brier 0.087) at ~10x lower cost.
# Sonnet 5.5 (claude-sonnet-5-5) stays the primary validated reference. Override with
# MAPPER_CLAUDE_MODEL in .env.
DEFAULT_CLAUDE_MODEL = "claude-haiku-5-5"
TEMPERATURE = 0.0
RETRY_STATUS = (429, 500, 502, 503, 529)   # rate limit / server busy: wait and ask again
RATE_LIMIT_TRIES = 6


class BackendError(RuntimeError):
    pass


_DOTENV_LOCK = threading.Lock()


def _load_dotenv_once():
    """Minimal .env reader (KEY=VALUE lines) so the team's .env works without python-dotenv.
    Thread-safe: with pilot --workers N several calls start at once, and the others must wait
    until the first has finished reading .env instead of seeing 'done' and finding no key."""
    if getattr(_load_dotenv_once, "done", False):
        return
    with _DOTENV_LOCK:
        if getattr(_load_dotenv_once, "done", False):
            return
        try:
            env_path = Path(__file__).resolve().parent.parent / ".env"
            if not env_path.exists():
                return
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key and value and key not in os.environ:
                    os.environ[key] = value
        finally:
            _load_dotenv_once.done = True      # only after the file has been read


def default_ollama_model() -> str:
    _load_dotenv_once()
    return os.environ.get("CLASSIFIER_MODEL", "llama3:8b")


def default_claude_model() -> str:
    _load_dotenv_once()
    return os.environ.get("MAPPER_CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL)


def call_claude_meta(system_prompt: str, user_message: str, model: str | None = None,
                     api_key: str | None = None, max_tokens: int = 4096) -> tuple[str, dict]:
    _load_dotenv_once()
    model = model or default_claude_model()
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise BackendError("No ANTHROPIC_API_KEY set (environment or .env).")
    t0 = time.time()
    # No `temperature`: newer Claude models (e.g. Sonnet 5.5) reject it as deprecated.
    # Replies can therefore vary a little between runs -- the same as in the chat-app
    # pilot, which is why Claude runs use --repeats.
    body = {"model": model, "max_tokens": max_tokens,
            # Prompt caching: the system prompt is identical on every call, so mark it
            # cacheable. Later calls within ~5 minutes re-read it at ~10% of the input
            # price. It caches the processed prompt, not answers -- replies are unchanged.
            "system": [{"type": "text", "text": system_prompt,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user_message}]}
    # Rate limit (429) or overload (529/5xx): wait and ask again, up to RATE_LIMIT_TRIES times,
    # so running several calls at once (pilot --workers N) does not turn a busy moment into
    # failed alerts. Any other status, or a network error, behaves as before.
    for attempt in range(1, RATE_LIMIT_TRIES + 1):
        try:
            resp = requests.post(
                ANTHROPIC_API_URL,
                headers={"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION,
                         "content-type": "application/json"},
                json=body, timeout=120,
            )
        except requests.RequestException as e:
            raise BackendError(f"Anthropic request failed after {int(time.time() - t0)}s: {e.__class__.__name__}") from e
        if resp.status_code not in RETRY_STATUS or attempt == RATE_LIMIT_TRIES:
            break
        try:
            wait = float(resp.headers.get("retry-after", ""))
        except ValueError:
            wait = 2.0 ** attempt
        time.sleep(min(max(wait, 1.0), 60.0))
    if resp.status_code != 200:
        raise BackendError(f"Anthropic API returned {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    # Newer models may put a `thinking` block before the answer; take the text block(s).
    texts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    if not texts or not "".join(texts).strip():
        raise BackendError(f"No text in Anthropic reply (stop_reason={data.get('stop_reason')!r}); "
                           f"block types: {[b.get('type') for b in data.get('content', [])]}")
    text = "".join(texts)
    usage = data.get("usage", {})
    cache_read = usage.get("cache_read_input_tokens") or 0
    cache_write = usage.get("cache_creation_input_tokens") or 0
    # input_tokens counts only the uncached part; report the full prompt size, plus the split.
    return text, {"model": model, "latency_ms": int((time.time() - t0) * 1000),
                  "input_tokens": (usage.get("input_tokens") or 0) + cache_read + cache_write,
                  "output_tokens": usage.get("output_tokens"),
                  "cache_read_tokens": cache_read, "cache_write_tokens": cache_write}


def call_ollama_meta(system_prompt: str, user_message: str, model: str | None = None,
                     host: str | None = None, num_ctx: int | None = None) -> tuple[str, dict]:
    _load_dotenv_once()
    model = model or default_ollama_model()
    host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    num_ctx = num_ctx or int(os.environ.get("OLLAMA_NUM_CTX", "12288"))
    timeout = int(os.environ.get("OLLAMA_TIMEOUT", "900"))
    t0 = time.time()
    try:
        resp = requests.post(
            f"{host.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "system", "content": system_prompt},
                             {"role": "user", "content": user_message}],
                "stream": False,
                "format": "json",  # constrain output to syntactically valid JSON
                # num_predict caps the reply: in JSON mode a small model sometimes never closes
                # the object and keeps emitting whitespace until the request times out.
                "options": {"temperature": TEMPERATURE, "num_ctx": num_ctx, "num_predict": 1024},
            },
            timeout=timeout,
        )
    except requests.RequestException as e:
        # A timeout or dropped connection on one alert is recorded as that alert's failure
        # instead of crashing the whole run.
        raise BackendError(f"Ollama request failed after {int(time.time() - t0)}s: {e.__class__.__name__}") from e
    if resp.status_code != 200:
        raise BackendError(f"Ollama returned {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    try:
        text = data["message"]["content"]
    except KeyError as e:
        raise BackendError(f"Unexpected Ollama response shape: {data!r}") from e
    meta = {"model": model, "latency_ms": int((time.time() - t0) * 1000),
            "input_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count")}
    # If Ollama read fewer prompt tokens than the prompt has, the window was too small.
    if meta["input_tokens"] is not None and meta["input_tokens"] >= num_ctx:
        meta["warning"] = f"prompt filled the whole {num_ctx}-token window; it may have been truncated"
    return text, meta


def call_claude(system_prompt: str, user_message: str, **kwargs) -> str:
    return call_claude_meta(system_prompt, user_message, **kwargs)[0]


def call_ollama(system_prompt: str, user_message: str, **kwargs) -> str:
    return call_ollama_meta(system_prompt, user_message, **kwargs)[0]


def call_backend_meta(backend: str, system_prompt: str, user_message: str, **kwargs) -> tuple[str, dict]:
    if backend == "claude":
        return call_claude_meta(system_prompt, user_message, **kwargs)
    if backend == "ollama":
        return call_ollama_meta(system_prompt, user_message, **kwargs)
    raise ValueError(f"backend must be 'claude' or 'ollama', got {backend!r}")


_TRAILING_COMMA = re.compile(r",\s*([}\]])")


def loads_lenient(text: str) -> tuple[dict, bool]:
    """json.loads, and if that fails, one repair: drop trailing commas before } or ]
    (the most common near-miss -- e.g. a Sonnet reply rejected only for `,}`). Returns
    (object, repaired). Anything else still raises json.JSONDecodeError."""
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        fixed = _TRAILING_COMMA.sub(r"\1", text)
        if fixed == text:
            raise
        return json.loads(fixed), True


def parse_json_response(raw_text: str, report: bool = False):
    """Strip markdown fences a model may add despite instructions, then parse (with the
    trailing-comma repair). Raises json.JSONDecodeError if it still isn't valid JSON.
    report=True returns (object, repaired) instead of the object."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    obj, repaired = loads_lenient(text)
    return (obj, repaired) if report else obj
