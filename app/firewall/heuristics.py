"""
Layer 2: Heuristic Scoring Engine
Scores prompts on structural and linguistic anomalies.
Does NOT need an API call — runs in microseconds.
"""

import re
import math
from typing import Tuple, List


# Weighted signals — each returns a score 0-100
# Final score = weighted average. Block threshold = configurable (default 80).

def _score_instruction_density(prompt: str) -> Tuple[float, str]:
    """High density of imperative verbs = suspicious."""
    imperative_patterns = [
        r"\b(ignore|disregard|forget|override|bypass|skip|pretend|act|behave|respond|output|print|reveal|show|tell)\b"
    ]
    words = prompt.split()
    if not words:
        return 0.0, ""

    count = sum(len(re.findall(p, prompt, re.IGNORECASE)) for p in imperative_patterns)
    density = count / max(len(words), 1)

    score = min(density * 500, 100)  # 20%+ imperative density = score 100
    label = f"imperative_density:{density:.2f}" if score > 20 else ""
    return score, label


def _score_role_switch_language(prompt: str) -> Tuple[float, str]:
    """Phrases that try to redefine the AI's identity."""
    patterns = [
        r"\byou are (now|a|an|the)\b",
        r"\byour (new )?role is\b",
        r"\bfrom now on\b",
        r"\bnew (persona|character|identity|instructions?)\b",
        r"\bforget (who|what) you are\b",
        r"\byou were previously\b",
        r"\bpretend (to be|you are|you.re)\b",
    ]
    hits = sum(1 for p in patterns if re.search(p, prompt, re.IGNORECASE))
    score = min(hits * 35, 100)
    label = f"role_switch_hits:{hits}" if hits > 0 else ""
    return score, label


def _score_authority_claim(prompt: str) -> Tuple[float, str]:
    """Claims of special authority or insider status."""
    patterns = [
        r"\b(i am|this is|speaking as).{0,20}(admin|developer|operator|owner|openai|anthropic|google|microsoft|system)\b",
        r"\b(special|elevated|admin|root|super)\s+(access|privilege|permission|mode)\b",
        r"\binternal (use|access|mode|command)\b",
    ]
    hits = sum(1 for p in patterns if re.search(p, prompt, re.IGNORECASE))
    score = min(hits * 50, 100)
    label = f"authority_claim_hits:{hits}" if hits > 0 else ""
    return score, label


def _score_length_anomaly(prompt: str) -> Tuple[float, str]:
    """Very long prompts often hide injections in noise."""
    length = len(prompt)
    if length > 3000:
        score = min((length - 3000) / 70, 100)
        return score, f"length:{length}"
    return 0.0, ""


def _score_entropy(prompt: str) -> Tuple[float, str]:
    """High character-level entropy can indicate encoded payloads."""
    if len(prompt) < 20:
        return 0.0, ""

    freq = {}
    for c in prompt:
        freq[c] = freq.get(c, 0) + 1

    entropy = -sum((f / len(prompt)) * math.log2(f / len(prompt)) for f in freq.values())

    # Normal English text: entropy ~4.0-4.5 bits
    # Base64/encoded: entropy ~5.5-6.0 bits
    if entropy > 5.2:
        score = min((entropy - 5.2) * 100, 100)
        return score, f"entropy:{entropy:.2f}"
    return 0.0, ""


def _score_multi_language_mixing(prompt: str) -> Tuple[float, str]:
    """Mixing languages/scripts can indicate obfuscation."""
    has_latin = bool(re.search(r'[a-zA-Z]', prompt))
    has_cjk = bool(re.search(r'[一-鿿぀-ヿ]', prompt))
    has_arabic = bool(re.search(r'[؀-ۿ]', prompt))
    has_special_unicode = bool(re.search(r'[ -⿿ﬀ-￾]', prompt))

    count = sum([has_latin, has_cjk, has_arabic, has_special_unicode])
    if count >= 3:
        return 70.0, f"multi_script_mixing:{count}"
    if has_special_unicode and has_latin:
        return 40.0, "unicode_mixing"
    return 0.0, ""


def _score_payload_markers(prompt: str) -> Tuple[float, str]:
    """Special tokens or markers often used in injection frameworks."""
    patterns = [
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"<\|system\|>",
        r"<\|user\|>",
        r"\[INST\]",
        r"\[/INST\]",
        r"<<SYS>>",
        r"<</SYS>>",
        r"<s>",
        r"\[SYSTEM\]",
        r"### Instruction:",
        r"### Response:",
        r"\[PROMPT\]",
        r"\[INPUT\]",
    ]
    hits = sum(1 for p in patterns if re.search(p, prompt, re.IGNORECASE))
    score = min(hits * 60, 100)
    label = f"payload_markers:{hits}" if hits > 0 else ""
    return score, label


# Weight table: (weight, scorer_fn)
SCORERS = [
    (0.25, _score_instruction_density),
    (0.25, _score_role_switch_language),
    (0.20, _score_authority_claim),
    (0.10, _score_length_anomaly),
    (0.05, _score_entropy),
    (0.05, _score_multi_language_mixing),
    (0.10, _score_payload_markers),
]


def run_heuristics(prompt: str, block_threshold: float = 80.0) -> Tuple[bool, float, List[str]]:
    """
    Score the prompt using all heuristic signals.

    Returns:
        triggered (bool): True if final score exceeds block_threshold
        final_score (float): Weighted score 0-100
        signals (List[str]): Active signal labels
    """
    total_weight = 0.0
    weighted_score = 0.0
    signals = []

    for weight, scorer in SCORERS:
        score, label = scorer(prompt)
        weighted_score += weight * score
        total_weight += weight
        if label:
            signals.append(label)

    final_score = weighted_score / total_weight if total_weight > 0 else 0.0
    triggered = final_score >= block_threshold

    return triggered, final_score, signals
