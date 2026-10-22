"""
mapper/live_ollama_test.py

Runs the 4 hand-written test alerts through a REAL local Ollama call (not
the dry-run harness in dry_run_test.py, which never touches a model).

Must be run on your actual machine (PowerShell), where the Ollama
container is actually reachable -- not from the dev bridge this was
written in.

Prerequisites:
  - `docker compose up -d ollama` is running (see docker-compose.yml).
  - The model is pulled: `ollama pull llama3:8b` (or run
    scripts/pull_models.ps1, which pulls it along with the others).
  - `requests` installed: `pip install requests` if you get a
    ModuleNotFoundError.

Run from the ai-attack-mapper/ directory:
    python -m mapper.live_ollama_test

This prints, for each test alert: the raw text Ollama returned, whether it
parsed as valid JSON, whether it passed schema validation, and -- if
valid -- a side-by-side of the category/sub-cluster/confidence it chose
vs. what the prompt doc documents as the expected answer. A mismatch here
is not necessarily a bug -- it's exactly the kind of data point the Model
Selection Pilot (Oct 4-8) needs, comparing this against the same alerts
run through Claude Sonnet 5.
"""

import json

from . import client, schema
from .test_alerts import TEST_ALERTS


def run(model: str = client.DEFAULT_OLLAMA_MODEL, host: str | None = None):
    results = []

    for case in TEST_ALERTS:
        name = case["name"]
        expected = case["expected_response"]
        print(f"--- {name} ---")

        from . import prompt as prompt_mod
        user_message = prompt_mod.build_user_message(
            case["alert_id"], case["source"], case["input"], case["output"]
        )

        try:
            raw_text = client.call_ollama(prompt_mod.SYSTEM_PROMPT, user_message, model=model, host=host)
        except client.BackendError as e:
            print(f"  BACKEND ERROR: {e}")
            results.append((name, "backend_error", str(e)))
            continue

        print(f"  raw response:\n{raw_text}\n")

        try:
            raw_json = client.parse_json_response(raw_text)
        except json.JSONDecodeError as e:
            print(f"  FAIL: response was not valid JSON: {e}")
            results.append((name, "invalid_json", raw_text))
            continue

        try:
            result = schema.validate(raw_json)
        except schema.SchemaValidationError as e:
            print(f"  FAIL: response did not match the output schema: {e}")
            results.append((name, "schema_invalid", raw_json))
            continue

        match = "MATCH" if result.category == expected["category"] else "DIFFERENT"
        print(f"  PASSED schema validation. Category: {result.category} (expected {expected['category']}, {match})")
        print(f"  Sub-cluster/theme: {result.sub_cluster_or_theme!r}")
        print(f"  Confidence: {result.confidence} (expected ~{expected['confidence']})")
        print(f"  Adversarial: {result.adversarial} (expected {expected['adversarial']})")
        print(f"  Rationale: {result.rationale}")
        results.append((name, "ok", result))

    print()
    print("=== Summary ===")
    for name, status, _ in results:
        print(f"  {status:16s} {name}")

    return results


if __name__ == "__main__":
    import sys
    override_model = sys.argv[1] if len(sys.argv) > 1 else client.DEFAULT_OLLAMA_MODEL
    run(model=override_model)
