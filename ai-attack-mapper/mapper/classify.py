"""
mapper/classify.py

Glue between prompt.py (what to ask), client.py (how to ask it), and
schema.py (how to validate / severity-score what comes back).

  classify_alert(...)       -> MapperResult (raises on failure). Unchanged signature.
  classify_alert_full(...)  -> Attempt: everything a caller needs to store the run,
                               success or failure (parsed JSON, raw text, tokens,
                               latency, error). Never raises for a bad model reply;
                               only a programming error escapes.

Retry: when a reply is not usable (not JSON, or fails schema validation),
classify_alert_full can ask once more, telling the model what was wrong. A
small local model often gets it right the second time. The number of
attempts is recorded so the pilot can still report first-try reliability.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from . import client, prompt, schema


class ClassificationError(RuntimeError):
    """A JSON-parse or schema-validation failure, with the model's raw text attached."""


@dataclass
class Attempt:
    ok: bool
    result: Optional[schema.MapperResult] = None   # validated + severity-scored
    parsed: Optional[dict] = None                   # the model's JSON as returned (for save_*)
    raw_text: Optional[str] = None
    error: Optional[str] = None
    attempts: int = 1
    meta: dict = field(default_factory=dict)       # model, latency_ms, input/output tokens (summed over attempts)


_ID_RE = re.compile(r"AML\.T\d{4}(?:\.\d{3})?|\bT\d{4}(?:\.\d{3})?\b|\bLLM\d{2}\b")


def _framework_of(bare_id: str) -> str:
    if bare_id.startswith("AML."):
        return "atlas"
    if bare_id.startswith("LLM"):
        return "owasp_llm"
    return "attack"


def normalize_framework_ids(parsed: dict) -> int:
    """Deterministic clean-up of framework_mapping, in place. Small models often write
    "AML.T0102 Generate Malicious Commands", cram several IDs into one string, or put an
    ATLAS ID in the ATT&CK list. This pulls every real-looking ID out of each element,
    files it under the framework its prefix belongs to, and de-duplicates, keeping the
    model's order (so its first ATLAS ID stays first). Tactic IDs (TA####) are kept as-is.
    The untouched reply is still stored as raw_output. Returns how many elements changed."""
    fm = parsed.get("framework_mapping")
    if not isinstance(fm, dict):
        return 0
    out = {"attack": [], "atlas": [], "owasp_llm": []}
    changed = 0
    for key in ("atlas", "attack", "owasp_llm"):  # atlas first: keeps its primary first
        items = fm.get(key) or []
        if not isinstance(items, list):
            items = [items]
        for item in items:
            text = str(item).strip()
            tactic = re.fullmatch(r"(AML\.)?TA\d{4}", text)
            found = [text] if tactic else _ID_RE.findall(text)
            if found != [text] or (found and _framework_of(found[0]) != key and not tactic):
                changed += 1
            for fid in found:
                dest = key if tactic else _framework_of(fid)
                if fid not in out[dest]:
                    out[dest].append(fid)
    for key in out:  # the prompt asks for at most 4; anything past 6 is list-dumping, not choice
        if len(out[key]) > 6:
            out[key] = out[key][:6]
            changed += 1
    parsed["framework_mapping"] = out
    return changed


def _retry_message(user_message: str, bad_reply: str, error: str) -> str:
    return (
        f"{user_message}\n\n"
        "Your previous reply could not be used:\n"
        f"  error: {error}\n"
        f"  reply started with: {bad_reply.strip()[:300]!r}\n"
        "Return ONLY the JSON object described in the output schema, with every required "
        "field, for the alert above."
    )


def classify_alert_full(alert_id, source: str, input_text: str, output_text: Optional[str],
                        backend: str = "claude", retries: int = 0, **backend_kwargs) -> Attempt:
    """retries: extra attempts after an unusable reply (0 = single attempt).
    Backend/network errors are returned as ok=False too (error starts with 'backend:')."""
    user_message = prompt.build_user_message(alert_id, source, input_text, output_text)
    message = user_message
    totals = {"latency_ms": 0, "input_tokens": 0, "output_tokens": 0}
    last = Attempt(ok=False)
    for n in range(1, retries + 2):
        try:
            raw_text, meta = client.call_backend_meta(backend, prompt.SYSTEM_PROMPT, message, **backend_kwargs)
        except client.BackendError as e:
            return Attempt(ok=False, error=f"backend: {e}", attempts=n, meta=totals)
        for k in totals:
            totals[k] += meta.get(k) or 0
        totals["model"] = meta.get("model")
        if meta.get("warning"):
            totals["warning"] = meta["warning"]
        try:
            parsed, repaired = client.parse_json_response(raw_text, report=True)
            if repaired:
                totals["json_repaired"] = True
            if not isinstance(parsed, dict):
                raise schema.SchemaValidationError(f"expected a JSON object, got {type(parsed).__name__}")
            fixed = normalize_framework_ids(parsed)
            if fixed:
                totals["ids_normalized"] = fixed
            result = schema.attach_severity(schema.validate(parsed))
            return Attempt(ok=True, result=result, parsed=parsed, raw_text=raw_text, attempts=n, meta=totals)
        except (json.JSONDecodeError, schema.SchemaValidationError) as e:
            last = Attempt(ok=False, raw_text=raw_text, error=f"{type(e).__name__}: {e}", attempts=n, meta=totals)
            message = _retry_message(user_message, raw_text, str(e))
    return last


def classify_alert(alert_id, source: str, input_text: str, output_text: Optional[str],
                   backend: str = "claude", **backend_kwargs) -> schema.MapperResult:
    """Validated, severity-scored MapperResult. Raises client.BackendError on a
    network/API failure, ClassificationError (raw text attached) on an unusable reply."""
    att = classify_alert_full(alert_id, source, input_text, output_text, backend=backend, **backend_kwargs)
    if att.ok:
        return att.result
    if att.error and att.error.startswith("backend: "):
        raise client.BackendError(att.error[len("backend: "):])
    snippet = (att.raw_text or "").strip().replace("\n", " ")[:300]
    raise ClassificationError(f"{att.error} -- raw model output: {snippet!r}")
