"""
rebuff_heuristics.py

Reused, unmodified in its matching logic, from the (now-archived)
Rebuff project: https://github.com/protectai/rebuff
File: python-sdk/rebuff/detect_pi_heuristics.py
License: Apache-2.0

Rebuff itself was archived May 16, 2025 and its full SDK requires an
OpenAI API key + Pinecone vector DB (conflicting with this project's
free/self-hosted decision for Detection). This one file is the
exception -- it has zero external dependencies (just `re` and
`difflib`, both standard library) and works entirely offline.

Provenance: pulled from Emmanuel's own reuse of this file
(`Capstone-AI-Attack-Mapper/ai-attack-mapper/detection/
rebuff_heuristics.py`, commit 878a892) rather than fetched from the
archived Rebuff repo directly, since he'd already done the identical
"is this file actually dependency-free" legwork and made the same
caching optimization noted below. Folded into this project's own
`heuristics.py` as a third detection signal alongside the existing
regex/substring matching -- see that file's module docstring for why
(PROGRESS_LOG.md, 2026-09-25 entry, has the full comparison against
Emmanuel's separately-built `heuristic_scanner.py`, including why this
one piece specifically was worth adopting and his LLM Guard wrapper /
NoRefusalLight output check were not, at least not yet).

What it does: generates a large set of injection-style phrasings from
combinations of verbs ("Ignore", "Disregard", ...), adjectives
("previous", "prior", ...), objects ("instructions", "commands", ...),
and prepositions, then fuzzy-matches an input string against all of
them using difflib.SequenceMatcher, returning a 0.0-1.0 similarity
score. This catches paraphrased injection attempts that don't hit any
fixed regex pattern -- a real gap in this project's original
regex-only `heuristics.py`.

MODIFICATION from the original (carried over from Emmanuel's reuse):
generate_injection_keywords() produces the same ~8,360 phrase
combinations every call regardless of input, so it's cached once at
module load (_ALL_INJECTION_KEYWORDS) instead of being regenerated on
every call. The original recomputed it per call (~2s/call), which made
batch evaluation (100+ prompts, or a live testbed handling real
traffic) too slow to be practical. Matching logic itself is unchanged
from upstream Rebuff.
"""

import re
from difflib import SequenceMatcher
from typing import List


def generate_injection_keywords() -> List[str]:
    """
    Generate all possible combinations of sentences based on a list of
    predefined verbs, adjectives, prepositions, and objects that can be
    used for prompt injection.

    Args:
        None

    Returns:
        List of sentences
    """
    verbs = [
        "Ignore",
        "Disregard",
        "Skip",
        "Forget",
        "Neglect",
        "Overlook",
        "Omit",
        "Bypass",
        "Pay no attention to",
        "Do not follow",
        "Do not obey",
    ]

    adjectives = [
        "",
        "prior",
        "previous",
        "preceding",
        "above",
        "foregoing",
        "earlier",
        "initial",
    ]

    prepositions = [
        "",
        "and start over",
        "and start anew",
        "and begin afresh",
        "and start from scratch",
    ]

    objects = [
        "content",
        "text",
        "instructions",
        "instruction",
        "directives",
        "directive",
        "commands",
        "command",
        "context",
        "conversation",
        "input",
        "inputs",
        "data",
        "message",
        "messages",
        "communication",
        "response",
        "responses",
        "request",
        "requests",
    ]

    # Generate all possible combinations of sentences
    injection_keywords = []
    for verb in verbs:
        for adjective in adjectives:
            for object in objects:
                for preposition in prepositions:
                    all_words = (
                        verb + " " + adjective + " " + object + " " + preposition
                    )
                    injection_keywords.append(all_words)

    return injection_keywords


# Cached once at module load -- see MODIFICATION note above. Keywords
# are normalized once here too, since normalization doesn't depend on
# the input text being scanned, only on the keyword itself.
_ALL_INJECTION_KEYWORDS = generate_injection_keywords()


def normalize_string(input_string: str) -> str:
    """
    Normalized input string by converting to lower case, remove
    characters that are not letters, remove excess white space etc.

    Args:
        input_string (str): String to be normalized

    Returns:
        normalized_string (str)
    """

    # Convert to lowercase
    result = input_string.lower()

    # Remove characters that are not letters, digits, spaces, or underscores
    result = re.sub(r"[^\w\s]|_", "", result)

    # Replace multiple consecutive spaces with a single space
    result = re.sub(r"\s+", " ", result)

    # Trim leading and trailing spaces
    normalized_string = result.strip()

    return normalized_string


# Pre-normalized keywords, computed once at module load (normalization
# doesn't depend on the input being scanned, only on the fixed keyword
# list) -- grouped by word count since
# detect_prompt_injection_using_heuristic_on_input needs substrings of
# matching length per keyword, and many of the ~8,800 keywords share
# the same length.
def _build_normalized_keyword_cache():
    cache = []
    for keyword_string in _ALL_INJECTION_KEYWORDS:
        normalized = normalize_string(keyword_string)
        words = normalized.split(" ")
        cache.append((normalized, words, len(words)))
    return cache


_NORMALIZED_KEYWORDS = _build_normalized_keyword_cache()


def get_input_substrings(normalized_input: str, keyword_length: int) -> List[str]:
    """
    Iterate over the input string and get substrings which have the
    same length as the keywords string.

    Args:
        normalized_input (str): Normalized input string
        keyword_length (int): The number of words in the injection string

    Returns:
        List of input substrings that have the same length as the
        number of keywords in injection string
    """
    words_in_input_string = normalized_input.split(" ")
    input_substrings = []
    number_of_substrings = len(words_in_input_string) - keyword_length + 1
    for i in range(number_of_substrings):
        input_substrings.append(" ".join(words_in_input_string[i : i + keyword_length]))

    return input_substrings


def get_matched_words_score(
    substring: str, keyword_parts: List[str], max_matched_words: int
) -> float:
    matched_words_count = len(
        [part for part, word in zip(keyword_parts, substring.split()) if word == part]
    )

    if matched_words_count > 0:
        base_score = 0.5 + 0.5 * min(matched_words_count / max_matched_words, 1)
    else:
        base_score = 0

    return base_score


def detect_prompt_injection_using_heuristic_on_input(input: str) -> float:
    highest_score = 0
    max_matched_words = 5

    normalized_input_string = normalize_string(input)
    # Substrings only depend on (input, keyword_length), not on the
    # keyword itself -- cache per length within this call so keywords
    # sharing a length (most of them) don't each regenerate the same
    # substrings.
    substrings_by_length = {}

    for normalized_keyword_string, keywords, keyword_length in _NORMALIZED_KEYWORDS:
        if keyword_length not in substrings_by_length:
            substrings_by_length[keyword_length] = get_input_substrings(
                normalized_input_string, keyword_length
            )
        input_substrings = substrings_by_length[keyword_length]

        # Calculate the similarity score between the keywords and each substring
        for substring in input_substrings:
            matched_word_score = get_matched_words_score(
                substring, keywords, max_matched_words
            )

            # If there's zero exact word-position overlap, the adjusted
            # score is guaranteed <= 0 (matched_word_score=0, and the
            # fuzzy similarity term can only subtract). It can never
            # exceed highest_score, which starts at 0 -- so skip the
            # expensive SequenceMatcher call entirely in that case.
            # This is a pure performance optimization: the mathematical
            # result is provably identical to always calling it, since
            # a zero-overlap substring never wins the max() regardless.
            if matched_word_score == 0:
                continue

            similarity_score = SequenceMatcher(
                None, substring, normalized_keyword_string
            ).ratio()

            # Adjust the score using the similarity score
            adjusted_score = matched_word_score - similarity_score * (
                1 / (max_matched_words * 2)
            )

            if adjusted_score > highest_score:
                highest_score = adjusted_score

    return highest_score
