"""
mapper/dry_run_test.py

The "first test round" requested Oct 3, 2026 -- run with NO live LLM call
(no API key configured, no Ollama reachable from this environment yet).

What this actually proves: given the model's documented EXPECTED response
for each of the 4 hand-written test alerts (test_alerts.py), does the
schema validator accept it, does severity-scoring run cleanly against it,
and does the DB-column flattening produce something sane.

Updated Oct 17, 2026: in_scope/adversarial/sub_cluster_or_theme/severity/
severity_score are now real columns (see alert_store/schema.sql and
schema.py's module docstring) -- this test checks them directly instead
of the old bracket-prefix-in-rationale workaround.

What this does NOT prove: that an actual model call (Sonnet 5 or
llama3:8b) will produce output matching these expectations. That's
evaluate.py's job once a backend is reachable -- see README.md.

Run: python3 -m mapper.dry_run_test   (from the ai-attack-mapper/ directory)
"""

from . import schema
from .test_alerts import TEST_ALERTS


def run():
    passed = 0
    failed = 0

    for case in TEST_ALERTS:
        name = case["name"]
        expected = case["expected_response"]
        print(f"--- {name} ---")
        try:
            result = schema.validate(expected)
        except schema.SchemaValidationError as e:
            print(f"  FAIL: schema rejected the documented expected response: {e}")
            failed += 1
            continue

        result = schema.attach_severity(result)

        try:
            db_row = schema.to_db_columns(result)
        except Exception as e:  # noqa: BLE001 -- want to see any flattening failure, not just the expected ones
            print(f"  FAIL: flattening to DB columns raised: {e}")
            failed += 1
            continue

        # Sanity checks beyond "did it not crash":
        problems = []
        if db_row["category"] != expected["category"]:
            problems.append(f"category mismatch: db={db_row['category']!r} expected={expected['category']!r}")
        if expected["in_scope"] and db_row["classification_confidence"] != expected["confidence"]:
            problems.append("confidence did not round-trip")
        if db_row.get("in_scope") != int(expected["in_scope"]):
            problems.append(
                f"in_scope did not round-trip to its own column: "
                f"db={db_row.get('in_scope')!r} expected={int(expected['in_scope'])!r}"
            )
        expected_adversarial = expected.get("adversarial")
        db_adversarial = db_row.get("adversarial")
        if expected_adversarial is not None and db_adversarial != int(expected_adversarial):
            problems.append(
                f"adversarial did not round-trip to its own column: "
                f"db={db_adversarial!r} expected={int(expected_adversarial)!r}"
            )
        if expected.get("sub_cluster_or_theme") and db_row.get("sub_cluster_or_theme") != expected["sub_cluster_or_theme"]:
            problems.append("sub_cluster_or_theme did not round-trip to its own column")
        if db_row.get("severity") not in schema.severity_mod.LEVELS:
            problems.append(f"severity not a recognized level: {db_row.get('severity')!r}")

        if problems:
            print("  FAIL:")
            for p in problems:
                print(f"    - {p}")
            failed += 1
            continue

        print("  PASS")
        print(f"    category={db_row['category']}  confidence={db_row['classification_confidence']}")
        print(f"    attck_technique={db_row['attck_technique']!r}")
        print(f"    atlas_technique={db_row['atlas_technique']!r}")
        print(f"    owasp_category={db_row['owasp_category']!r}")
        print(f"    severity={db_row.get('severity')!r} (score={db_row.get('severity_score')}) -- {result.severity_rationale}")
        print(f"    rationale={db_row['rationale']!r}")
        passed += 1

    print()
    print(f"{passed} passed, {failed} failed, out of {len(TEST_ALERTS)} test alerts")
    return failed == 0


if __name__ == "__main__":
    import sys
    ok = run()
    sys.exit(0 if ok else 1)
