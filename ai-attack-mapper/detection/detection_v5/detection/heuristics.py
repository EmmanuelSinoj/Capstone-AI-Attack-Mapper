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
from .preprocessing import normalize_for_detection, decode_candidates

# Original 12 patterns. Two are corrected here (marked below) -- both had
# a real bug found while testing today's additions: they only allowed ONE
# qualifier word between the verb and the noun, so the single most classic
# phrasing, "ignore all previous instructions", never actually matched
# either pattern. It was only ever caught because the fuzzy matcher (or a
# second clause in the same sentence) happened to catch it instead. Fixed
# to allow the natural two-qualifier-word form; verified against every
# phrasing variant before and after the fix.
_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+|any\s+|the above\s+)?(?:previous\s+|prior\s+)?instructions", re.I), "instruction_override"),  # FIXED
    (re.compile(r"disregard\s+(?:all\s+|any\s+|your\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|guidelines)", re.I), "instruction_override"),  # FIXED
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

# New: structural markup / chat-template injection -- exact matches for
# fake special tokens an attacker inserts to trick the model into
# thinking a new instruction block has started. Zero overlap with
# ordinary prose, so this carries the same low false-positive profile
# as the original patterns.
_STRUCTURAL_PATTERNS = [
    (re.compile(r"\[/?INST\]", re.I), "structural_markup"),
    (re.compile(r"<\|im_(start|end)\|>", re.I), "structural_markup"),
    (re.compile(r"###\s*(Instruction|System)\s*:", re.I), "structural_markup"),
    (re.compile(r"</?system>", re.I), "structural_markup"),
    (re.compile(r"<\|system\|>", re.I), "structural_markup"),
    (re.compile(r"\[/?SYS\]", re.I), "structural_markup"),
]

# New: broader exact-match coverage, independently written (not derived
# from looking at our own benchmark's misses -- see PROGRESS_LOG for why
# that specific approach was rejected after the v3/narrow-phrase tests).
_EXPANDED_PATTERNS = [
    (re.compile(r"forget (your|all|any) (instructions|training|guidelines)", re.I), "instruction_override"),
    (re.compile(r"start (over|fresh) (completely|entirely) (with|and) (no|without) (rules|restrictions)", re.I), "instruction_override"),
    (re.compile(r"new instructions (supersede|override|replace) (all|any) prior", re.I), "instruction_override"),
    (re.compile(r"(debug|maintenance|test) mode (is )?(enabled|activated|on)", re.I), "persona_jailbreak"),
    (re.compile(r"no ethical (guidelines|constraints|restrictions)", re.I), "persona_jailbreak"),
    (re.compile(r"without (any )?(limitations|restrictions|rules)", re.I), "persona_jailbreak"),
    (re.compile(r"\b(unshackled|uncensored) (version|mode|ai)\b", re.I), "persona_jailbreak"),
    (re.compile(r"(evil|opposite) (twin|day) mode", re.I), "persona_jailbreak"),
    (re.compile(r"print your (configuration|guidelines)", re.I), "prompt_exfiltration"),  # narrowed to "your" only -- "print the configuration" false-positived on ordinary IT text ("print the configuration of my network adapter")
    (re.compile(r"what is your (system )?prompt", re.I), "prompt_exfiltration"),
    (re.compile(r"show (me )?your (rules|guidelines|instructions)", re.I), "prompt_exfiltration"),
    (re.compile(r"output your (guidelines|instructions|configuration)", re.I), "prompt_exfiltration"),
    (re.compile(r"as your (creator|developer|maker)", re.I), "authority_claim"),
    (re.compile(r"(admin|developer) override (code)?", re.I), "authority_claim"),
    (re.compile(r"content policy (is )?(off|disabled)", re.I), "filter_bypass"),
    (re.compile(r"safety (is )?(off|disabled)", re.I), "filter_bypass"),
    (re.compile(r"(restrictions|guardrails) (are )?(disabled|removed|lifted)", re.I), "filter_bypass"),
    (re.compile(r"respond (only )?in base ?64", re.I), "encoding_request"),
    (re.compile(r"encode your (reply|response) in", re.I), "encoding_request"),
    (re.compile(r"use rot ?13", re.I), "encoding_request"),
]

_ALL_PATTERNS = _PATTERNS + _STRUCTURAL_PATTERNS + _EXPANDED_PATTERNS

REBUFF_SCORE_THRESHOLD = 0.65

# NOTE: a length-aware version of this threshold was tested (raising the
# cutoff for longer prompts to reduce false alarms). It genuinely reduces
# false positives on long real prompts (57% -> 9%), but recall drops by
# almost exactly the same amount (58% -> 9%), so it is not a clear
# improvement -- see the project's v5 README/history for the full
# calibration data. Deliberately left OUT of this build pending the
# Garak/PyRIT test against the live testbed, which will show the real
# attack-length distribution this decision should be based on. Flat 0.65
# is used below, unchanged from v4.


def _check_rebuff(prompt: str) -> Tuple[bool, float]:
    if not prompt:
        return False, 0.0
    prompt = normalize_for_detection(prompt)
    score = detect_prompt_injection_using_heuristic_on_input(prompt)
    return score >= REBUFF_SCORE_THRESHOLD, score


def check(text: str) -> Tuple[bool, List[str]]:
    if not text:
        return False, []
    normalized = normalize_for_detection(text)

    # Check the text as given, then also check anything it decodes to
    # (base64/hex/ROT13) -- an attacker hiding "ignore instructions"
    # inside a base64 blob should be caught the same as typing it plainly.
    texts_to_check = [normalized] + [normalize_for_detection(c) for c in decode_candidates(text)]

    matched = set()
    for t in texts_to_check:
        for pattern, name in _ALL_PATTERNS:
            if pattern.search(t):
                matched.add(name)
    return (len(matched) > 0), sorted(matched)


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
