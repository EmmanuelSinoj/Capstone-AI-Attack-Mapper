"""
mapper/evaluate.py

Quick check on the 4 hand-written test alerts in test_alerts.py. The real
Model Selection Pilot (40 synthetic alerts, dev / held-out split) is
pilot.py -- use that for any number you report.

Runs a labeled set of alerts through classify_alert() for one or more
backends, scores each prediction against its documented ground truth, and
prints/saves a report. This is the Model Selection Pilot harness (Trello,
[Week 2] Gladwin -- "Build the model selection pilot harness") plus a
general-purpose classification accuracy evaluator usable again once
Shadi's larger labeled synthetic batch lands.

What it scores, per alert:
  - category match (predicted vs. expected A/B/C/D/null)
  - adversarial match (bool)
  - confidence absolute error (|predicted - expected|)
  - per-framework precision/recall (ATT&CK, ATLAS, OWASP LLM Top 10) --
    set-based, since both predicted and expected are ID lists
  - severity (reported, not graded -- there's no external ground-truth
    label for severity; it's our own deterministic derivation, see
    severity.py)
  - structured-output reliability: did the backend return something that
    parsed as JSON and passed schema validation at all? A backend that
    scores well on category accuracy but fails validation half the time
    is not actually the better choice -- this is tracked separately so
    it doesn't get silently averaged away.

Usage (from ai-attack-mapper/, with the venv that has `requests` active):
    python -m mapper.evaluate --backend ollama
    python -m mapper.evaluate --backend claude
    python -m mapper.evaluate --backend both
    python -m mapper.evaluate --backend ollama --model mistral:7b-instruct-q4_K_M
    python -m mapper.evaluate --alerts path/to/larger_labeled_set.json

Requires, for --backend ollama: `docker compose up -d ollama` running and
the model pulled (scripts/pull_models.ps1). For --backend claude:
ANTHROPIC_API_KEY set in the environment (or passed via --api-key).
"""

import argparse
import json
import time
import traceback

from . import client, prompt, schema
from .test_alerts import TEST_ALERTS


def _load_alerts(path):
    if path is None:
        return TEST_ALERTS
    with open(path) as f:
        return json.load(f)


def _framework_score(predicted_ids, expected_ids):
    """
    Set-based precision/recall, returned as (precision, recall) where
    either can be None if undefined for this alert (never silently
    defaulted to 1.0 -- an earlier version of this function did that for
    "nothing expected", which inflated recall whenever ground truth simply
    didn't populate a framework for that alert; summarize()'s mean_of()
    already drops None values from the average rather than treating them
    as perfect scores).
    """
    predicted, expected = set(predicted_ids), set(expected_ids)
    if not expected:
        # Recall is undefined (0/0) when nothing was expected -- precision
        # still applies: perfect if the model also returned nothing,
        # 0.0 if it populated IDs that shouldn't be there at all.
        return (1.0 if not predicted else 0.0), None
    if not predicted:
        return 0.0, 0.0
    true_positive = len(predicted & expected)
    precision = true_positive / len(predicted)
    recall = true_positive / len(expected)
    return precision, recall


def run_backend(backend: str, alerts: list, **backend_kwargs) -> list:
    """
    Deliberately does NOT just call classify.classify_alert() -- it inlines
    the same three steps (call backend -> parse JSON -> validate+score) so
    that raw_text is captured and attached to the row on EVERY path,
    success or failure. A schema failure with only "missing field X" and
    no view of what the model actually said is close to undiagnosable;
    this is what let us see, on the first real Ollama run, that
    llama3.2:latest was dropping the `adversarial` key specifically rather
    than returning garbage wholesale.
    """
    rows = []
    for case in alerts:
        alert_id = case["alert_id"]
        name = case.get("name", alert_id)
        expected = case["expected_response"]
        row = {"name": name, "alert_id": alert_id}
        t0 = time.time()
        raw_text = None
        try:
            user_message = prompt.build_user_message(
                alert_id, case["source"], case["input"], case.get("output")
            )
            if backend == "claude":
                raw_text = client.call_claude(prompt.SYSTEM_PROMPT, user_message, **backend_kwargs)
            elif backend == "ollama":
                raw_text = client.call_ollama(prompt.SYSTEM_PROMPT, user_message, **backend_kwargs)
            else:
                raise ValueError(f"backend must be 'claude' or 'ollama', got {backend!r}")

            raw_json = client.parse_json_response(raw_text)
            result = schema.validate(raw_json)
            result = schema.attach_severity(result)

            row["elapsed_s"] = round(time.time() - t0, 2)
            row["status"] = "ok"
            row["predicted_category"] = result.category
            row["expected_category"] = expected.get("category")
            row["category_match"] = result.category == expected.get("category")
            row["predicted_adversarial"] = result.adversarial
            row["expected_adversarial"] = expected.get("adversarial")
            row["adversarial_match"] = result.adversarial == expected.get("adversarial")

            if expected.get("confidence") is not None and result.confidence is not None:
                row["confidence_abs_error"] = round(abs(result.confidence - expected["confidence"]), 3)
            else:
                row["confidence_abs_error"] = None

            fm_expected = expected.get("framework_mapping", {})
            malformed_ids = []
            for fw in ("attack", "atlas", "owasp_llm"):
                predicted_ids = getattr(result, f"framework_{fw}")
                # A model that doesn't strictly follow "array of short ID
                # strings" sometimes crams several IDs into one comma-joined
                # element instead -- that element then won't set-match
                # anything in the expected list, and this is worth
                # surfacing as its own reliability signal rather than just
                # silently tanking precision/recall with no explanation.
                malformed_ids += [pid for pid in predicted_ids if "," in pid]
                precision, recall = _framework_score(predicted_ids, fm_expected.get(fw, []))
                row[f"{fw}_precision"] = round(precision, 2) if precision is not None else None
                row[f"{fw}_recall"] = round(recall, 2) if recall is not None else None
            row["malformed_framework_ids"] = malformed_ids

            row["severity"] = result.severity
            row["severity_rationale"] = result.severity_rationale
            row["rationale"] = result.rationale
        except client.BackendError as e:
            row["status"] = "backend_error"
            row["error"] = str(e)
        except (schema.SchemaValidationError, json.JSONDecodeError) as e:
            row["status"] = "invalid_output"
            row["error"] = str(e)
        except Exception as e:  # noqa: BLE001 -- surface any evaluator-side bug too, don't let it kill the run
            row["status"] = "evaluator_error"
            row["error"] = repr(e)
            row["traceback"] = traceback.format_exc()
        finally:
            if raw_text is not None:
                row["raw_text"] = raw_text[:2000]
        rows.append(row)
    return rows


def summarize(rows: list, backend_label: str) -> dict:
    total = len(rows)
    ok_rows = [r for r in rows if r["status"] == "ok"]
    n_ok = len(ok_rows)

    def mean_of(key):
        values = [r[key] for r in ok_rows if r.get(key) is not None]
        return round(sum(values) / len(values), 3) if values else None

    conf_errors = [r["confidence_abs_error"] for r in ok_rows if r.get("confidence_abs_error") is not None]

    return {
        "backend": backend_label,
        "total_alerts": total,
        "structured_output_reliability": round(n_ok / total, 3) if total else 0.0,
        "category_accuracy": round(sum(1 for r in ok_rows if r["category_match"]) / n_ok, 3) if n_ok else None,
        "adversarial_accuracy": round(sum(1 for r in ok_rows if r["adversarial_match"]) / n_ok, 3) if n_ok else None,
        "mean_confidence_abs_error": round(sum(conf_errors) / len(conf_errors), 3) if conf_errors else None,
        "attack_mean_precision": mean_of("attack_precision"),
        "attack_mean_recall": mean_of("attack_recall"),
        "atlas_mean_precision": mean_of("atlas_precision"),
        "atlas_mean_recall": mean_of("atlas_recall"),
        "owasp_llm_mean_precision": mean_of("owasp_llm_precision"),
        "owasp_llm_mean_recall": mean_of("owasp_llm_recall"),
    }


def print_report(backend_label: str, rows: list, summary: dict) -> None:
    print(f"\n=== {backend_label} ===")
    for r in rows:
        if r["status"] == "ok":
            flag = "MATCH" if r["category_match"] else "DIFF"
            print(
                f"  [OK]   {r['name']} -- category {r['predicted_category']} "
                f"(expected {r['expected_category']}, {flag}), "
                f"severity={r['severity']}, conf_err={r['confidence_abs_error']}, "
                f"{r['elapsed_s']}s"
            )
            if r.get("malformed_framework_ids"):
                print(f"         malformed framework IDs (comma-joined into one element): {r['malformed_framework_ids']}")
        else:
            print(f"  [FAIL:{r['status']}] {r['name']} -- {str(r.get('error', ''))[:200]}")
            if r.get("raw_text") is not None:
                print(f"         raw model output: {r['raw_text'][:500]!r}")
            if r.get("traceback"):
                print(f"         traceback:\n{r['traceback']}")

    print("\n  --- summary ---")
    for k, v in summary.items():
        print(f"  {k}: {v}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the Mapper's classification accuracy / model-selection evaluation."
    )
    parser.add_argument("--backend", choices=["ollama", "claude", "both"], default="ollama")
    parser.add_argument("--model", default=None, help="Override the backend's default model.")
    parser.add_argument("--host", default=None, help="Ollama host override (default http://localhost:11434).")
    parser.add_argument("--api-key", default=None, help="Anthropic API key override (default: ANTHROPIC_API_KEY env var).")
    parser.add_argument(
        "--alerts", default=None,
        help="Path to a JSON file of labeled alerts (same shape as test_alerts.TEST_ALERTS). "
             "Defaults to the 4 built-in hand-written samples.",
    )
    parser.add_argument("--out", default=None, help="Path to write full JSON results+summary.")
    args = parser.parse_args(argv)

    alerts = _load_alerts(args.alerts)
    backends = ["ollama", "claude"] if args.backend == "both" else [args.backend]

    all_results = {}
    for backend in backends:
        kwargs = {}
        if args.model:
            kwargs["model"] = args.model
        if backend == "ollama" and args.host:
            kwargs["host"] = args.host
        if backend == "claude" and args.api_key:
            kwargs["api_key"] = args.api_key

        rows = run_backend(backend, alerts, **kwargs)
        summary = summarize(rows, backend)
        print_report(backend, rows, summary)
        all_results[backend] = {"rows": rows, "summary": summary}

    if len(backends) == 2:
        print("\n=== Pilot decision inputs (ollama vs claude) ===")
        ollama_summary, claude_summary = all_results["ollama"]["summary"], all_results["claude"]["summary"]
        for k in (
            "structured_output_reliability", "category_accuracy",
            "adversarial_accuracy", "mean_confidence_abs_error",
        ):
            print(f"  {k}: ollama={ollama_summary.get(k)}  claude={claude_summary.get(k)}")

    out_path = args.out
    if out_path is None:
        ts = time.strftime("%Y%m%dT%H%M%S")
        out_path = f"evaluation/mapper_eval_{'_'.join(backends)}_{ts}.json"
    import os
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
