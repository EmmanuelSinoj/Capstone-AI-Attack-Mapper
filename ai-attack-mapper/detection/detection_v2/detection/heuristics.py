"""
Heuristic pattern-based prompt-injection / jailbreak detector.

Fast, cheap, synchronous first-pass filter -- runs on every testbed
interaction before the judge model gets a look. See
live_attack_path/detection/README.md for how this fits into the
overall detection layer, and docs/architecture.md for the full
Live Attack Path diagram this is one box of.
"""

import re
from typing import List, Tuple

from .rebuff_heuristics import detect_prompt_injection_using_heuristic_on_input

_PATTERNS = [
    (re.compile(r"ignore (all|any|previous|prior|the above) instructions", re.I), "instruction_override"),
    (re.compile(r"disregard (all|any|previous|prior|your) (instructions|rules|guidelines)", re.I), "instruction_override"),
    (re.compile(r"you are (now|no longer) (DAN|in developer mode|unrestricted)", re.I), "persona_jailbreak"),
    (re.compile(r"reveal (your|the) (system prompt|instructions|configuration)", re.I), "prompt_exfiltration"),
    (re.compile(r"print (your|the) (system prompt|instructions)", re.I), "prompt_exfiltration"),
    (re.compile(r"pretend (you are|to be).*(without|no) (restrictions|rules|filters)", re.I), "persona_jailbreak"),
    (re.compile(r"act as (if|though) you (have no|do not have) (restrictions|guidelines)", re.I), "persona_jailbreak"),
    (re.compile(r"\bDAN\b.*(mode|prompt)", re.I), "persona_jailbreak"),
    (re.compile(r"bypass (your|the|all) (safety|content) (filters|guidelines|restrictions)", re.I), "filter_bypass"),
    (re.compile(r"(sudo|admin|root) mode", re.I), "privilege_escalation_roleplay"),
    (re.compile(r"repeat (the words?|everything) (above|before this)", re.I), "prompt_exfiltration"),
    (re.compile(r"what (is|was) your (system prompt|initial instructions)", re.I), "prompt_exfiltration"),
]

REBUFF_SCORE_THRESHOLD = 0.65


def _check_rebuff(prompt: str) -> Tuple[bool, float]:
    if not prompt:
        return False, 0.0
    score = detect_prompt_injection_using_heuristic_on_input(prompt)
    return score >= REBUFF_SCORE_THRESHOLD, score


def check(text: str) -> Tuple[bool, List[str]]:
    if not text:
        return False, []
    matched = [name for pattern, name in _PATTERNS if pattern.search(text)]
    return (len(matched) > 0), matched


def check_interaction(prompt: str, response: str) -> Tuple[bool, List[str], float]:
    prompt_flagged, prompt_matches = check(prompt)
    response_flagged, response_matches = check(response)
    rebuff_flagged, rebuff_score = _check_rebuff(prompt)

    rebuff_matches = [f"rebuff_fuzzy({rebuff_score:.2f})"] if rebuff_flagged else []
    all_matches = sorted(set(prompt_matches + response_matches + rebuff_matches))
    flagged = prompt_flagged or response_flagged or rebuff_flagged

    if not flagged:
        confidence = 0.0
    elif response_flagged:
        confidence = 0.9
    elif prompt_flagged:
        confidence = 0.5
    else:
        confidence = rebuff_score

    return flagged, all_matches, confidence
