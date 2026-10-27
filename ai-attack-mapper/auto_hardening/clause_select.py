#!/usr/bin/env python3
"""clause_select.py -- which clauses.json key an attack gets (Auto-Hardening v2, Upgrade 1). Shared by gate.py and harden.py.

Two methods:
  probe   the attack family from Garak's probe_id (longest clauses.json key that prefixes it). This is the v1 behaviour.
  mapper  the Mapper's own framework mapping (ATLAS + OWASP IDs), looked up in technique_map.json. If none of the Mapper's
          IDs is in the table, fall back to the probe family, then to the 'default' clause.

Stdlib only; parse_ids mirrors mapper/framework_reference.parse_id_list so auto_hardening does not import the mapper package.
"""
import json, pathlib

HERE = pathlib.Path(__file__).parent


def load_clauses():
    return json.load(open(HERE / "clauses.json", encoding="utf-8"))


def load_technique_map():
    return json.load(open(HERE / "technique_map.json", encoding="utf-8"))["rules"]


def parse_ids(value):
    """An ID-list column (JSON text, comma-joined text, a list, or None) as a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        text = str(value).strip()
        if not text:
            return []
        try:
            items = json.loads(text)
            if not isinstance(items, list):
                items = [items]
        except json.JSONDecodeError:
            items = text.split(",")
    return [str(i).strip() for i in items if i is not None and str(i).strip()]


def probe_key(family, clauses):
    """Longest clauses.json key (not 'default') that prefixes the probe family, or None."""
    best = None
    for key in clauses:
        if key != "default" and (family or "").startswith(key) and (best is None or len(key) > len(best)):
            best = key
    return best


def mapper_key(ids, rules):
    """(clause key, matching Mapper ID) for the first rule with a matching ID, or (None, None)."""
    for rule in rules:
        for mid in ids:
            for rid in rule["ids"]:
                if mid == rid or mid.startswith(rid + "."):
                    return rule["clause"], mid
    return None, None


def select(family, mapper_ids, method, clauses, rules):
    """(clause key, how it was chosen). method is 'probe' or 'mapper'."""
    probe = probe_key(family, clauses)
    if method == "mapper":
        key, mid = mapper_key(mapper_ids, rules)
        if key:
            return key, "mapper:" + mid
        if probe:
            return probe, "probe (no Mapper match)"
        return "default", "default (no match)"
    if probe:
        return probe, "probe"
    return "default", "default"
