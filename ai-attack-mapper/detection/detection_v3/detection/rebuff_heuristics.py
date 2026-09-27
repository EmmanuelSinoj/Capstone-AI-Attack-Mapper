import re
from difflib import SequenceMatcher
from typing import List


def generate_injection_keywords() -> List[str]:
    verbs = [
        "Ignore", "Disregard", "Skip", "Forget", "Neglect", "Overlook",
        "Omit", "Bypass", "Pay no attention to", "Do not follow", "Do not obey",
    ]

    adjectives = [
        "", "prior", "previous", "preceding", "above", "foregoing", "earlier", "initial",
    ]

    prepositions = [
        "", "and start over", "and start anew", "and begin afresh", "and start from scratch",
    ]

    objects = [
        "content", "text", "instructions", "instruction", "directives", "directive",
        "commands", "command", "context", "conversation", "input", "inputs", "data",
        "message", "messages", "communication", "response", "responses", "request", "requests",
    ]

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


_ALL_INJECTION_KEYWORDS = generate_injection_keywords()


def generate_reveal_prompt_keywords() -> List[str]:
    """
    Second phrase family: exfiltration asks ("reveal/print your system
    prompt"). The original Rebuff algorithm only ever generated
    instruction-override phrasing ("ignore previous instructions") --
    it has zero fuzzy coverage for this equally common attack family,
    which previously relied entirely on exact regex matches in
    heuristics.py's _PATTERNS list.
    """
    verbs = ["Reveal", "Print", "Show", "Disclose", "Output", "Share", "Tell me"]
    determiners = ["your", "the"]
    objects = [
        "system prompt", "instructions", "configuration", "initial instructions",
        "original prompt", "rules", "guidelines",
    ]
    keywords = []
    for v in verbs:
        for d in determiners:
            for o in objects:
                keywords.append(f"{v} {d} {o}")
    return keywords


def generate_unrestricted_persona_keywords() -> List[str]:
    """
    Third phrase family: persona/jailbreak asks ("act as an
    unrestricted AI"). Same gap as above -- previously relied entirely
    on the DAN-specific regex pattern, with no fuzzy coverage for
    paraphrases of the same underlying ask.
    """
    verbs = ["Act as", "Become", "Pretend to be", "Roleplay as", "Simulate being", "Behave like"]
    adjectives = ["an unrestricted", "a jailbroken", "an unfiltered", "a DAN", "an uncensored"]
    objects = ["AI", "assistant", "model", "chatbot"]
    keywords = []
    for v in verbs:
        for a in adjectives:
            for o in objects:
                keywords.append(f"{v} {a} {o}")
    return keywords


# EXPANDED keyword set: original instruction-override family plus the
# two new families above. Matching algorithm below is completely
# unchanged -- this only widens what it's comparing against.
_ALL_INJECTION_KEYWORDS = (
    _ALL_INJECTION_KEYWORDS
    + generate_reveal_prompt_keywords()
    + generate_unrestricted_persona_keywords()
)


def normalize_string(input_string: str) -> str:
    result = input_string.lower()
    result = re.sub(r"[^\w\s]|_", "", result)
    result = re.sub(r"\s+", " ", result)
    normalized_string = result.strip()
    return normalized_string


def _build_normalized_keyword_cache():
    cache = []
    for keyword_string in _ALL_INJECTION_KEYWORDS:
        normalized = normalize_string(keyword_string)
        words = normalized.split(" ")
        cache.append((normalized, words, len(words)))
    return cache


_NORMALIZED_KEYWORDS = _build_normalized_keyword_cache()


def get_input_substrings(normalized_input: str, keyword_length: int) -> List[str]:
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
    substrings_by_length = {}

    for normalized_keyword_string, keywords, keyword_length in _NORMALIZED_KEYWORDS:
        if keyword_length not in substrings_by_length:
            substrings_by_length[keyword_length] = get_input_substrings(
                normalized_input_string, keyword_length
            )
        input_substrings = substrings_by_length[keyword_length]

        for substring in input_substrings:
            matched_word_score = get_matched_words_score(
                substring, keywords, max_matched_words
            )

            if matched_word_score == 0:
                continue

            similarity_score = SequenceMatcher(
                None, substring, normalized_keyword_string
            ).ratio()

            adjusted_score = matched_word_score - similarity_score * (
                1 / (max_matched_words * 2)
            )

            if adjusted_score > highest_score:
                highest_score = adjusted_score

    return highest_score
