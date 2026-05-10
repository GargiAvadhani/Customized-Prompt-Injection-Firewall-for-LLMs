"""
Main Firewall Orchestrator
Coordinates all three detection layers and produces a final verdict.
"""

import hashlib
import time
import os
from typing import Optional

from app.models import FirewallResponse, LayerResult, Verdict, ThreatCategory
from app.firewall.rules import run_rules
from app.firewall.heuristics import run_heuristics
from app.firewall.llm_classifier import classify_with_llm


def _hash_prompt(prompt: str) -> str:
    """Return first 16 chars of SHA-256 hash. Never stores raw prompt."""
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


def _map_threat_category(category_str: str) -> ThreatCategory:
    """Safely map a string to ThreatCategory enum."""
    try:
        return ThreatCategory(category_str.upper())
    except ValueError:
        return ThreatCategory.UNKNOWN


def inspect(prompt: str, session_id: Optional[str] = None, context: Optional[str] = None) -> FirewallResponse:
    """
    Run the full 3-layer detection pipeline.

    Pipeline logic:
    1. Run regex rules → if triggered with confidence >= 0.90, BLOCK immediately.
    2. Run heuristics → if score >= HEURISTIC_BLOCK_THRESHOLD, BLOCK immediately.
    3. Run LLM classifier → final verdict.

    Returns a fully populated FirewallResponse.
    """
    start_time = time.perf_counter()
    layers: list[LayerResult] = []

    heuristic_threshold = float(os.getenv("HEURISTIC_BLOCK_THRESHOLD", "80"))
    enable_llm = os.getenv("ENABLE_LLM_LAYER", "true").lower() == "true"

    # ── LAYER 1: REGEX RULES ───────────────────────────────────────────────
    rule_triggered, rule_confidence, matched_rules, rule_category = run_rules(prompt)

    layers.append(LayerResult(
        layer_name="regex_rules",
        triggered=rule_triggered,
        confidence=rule_confidence,
        matched_rules=matched_rules,
        explanation=f"Matched rules: {', '.join(matched_rules)}" if matched_rules else "No rules matched"
    ))

    if rule_triggered:
        elapsed = (time.perf_counter() - start_time) * 1000
        return FirewallResponse(
            verdict=Verdict.BLOCK,
            threat_category=_map_threat_category(rule_category),
            confidence=rule_confidence,
            explanation=f"Blocked by regex rules: {', '.join(matched_rules)}",
            layers=layers,
            processing_time_ms=round(elapsed, 2),
            prompt_hash=_hash_prompt(prompt),
            blocked_by_layer="regex_rules",
        )

    # ── LAYER 2: HEURISTICS ────────────────────────────────────────────────
    heuristic_triggered, heuristic_score, signals = run_heuristics(prompt, block_threshold=heuristic_threshold)
    heuristic_confidence = heuristic_score / 100.0

    layers.append(LayerResult(
        layer_name="heuristics",
        triggered=heuristic_triggered,
        confidence=heuristic_confidence,
        score=heuristic_score,
        matched_rules=signals,
        explanation=f"Heuristic score: {heuristic_score:.1f}/100. Signals: {', '.join(signals)}" if signals else f"Heuristic score: {heuristic_score:.1f}/100"
    ))

    if heuristic_triggered:
        elapsed = (time.perf_counter() - start_time) * 1000
        return FirewallResponse(
            verdict=Verdict.BLOCK,
            threat_category=ThreatCategory.UNKNOWN,
            confidence=heuristic_confidence,
            explanation=f"Blocked by heuristics (score {heuristic_score:.1f}/100). Signals: {', '.join(signals)}",
            layers=layers,
            processing_time_ms=round(elapsed, 2),
            prompt_hash=_hash_prompt(prompt),
            blocked_by_layer="heuristics",
        )

    # ── LAYER 3: LLM CLASSIFIER ────────────────────────────────────────────
    if not enable_llm:
        elapsed = (time.perf_counter() - start_time) * 1000
        layers.append(LayerResult(
            layer_name="llm_classifier",
            triggered=False,
            confidence=0.0,
            explanation="LLM layer disabled"
        ))
        return FirewallResponse(
            verdict=Verdict.ALLOW,
            threat_category=ThreatCategory.BENIGN,
            confidence=1.0 - heuristic_confidence,
            explanation="Passed all layers (LLM layer disabled)",
            layers=layers,
            processing_time_ms=round(elapsed, 2),
            prompt_hash=_hash_prompt(prompt),
        )

    llm_verdict, llm_category, llm_confidence, llm_explanation = classify_with_llm(prompt, context)
    llm_triggered = llm_verdict == "BLOCK"

    layers.append(LayerResult(
        layer_name="llm_classifier",
        triggered=llm_triggered,
        confidence=llm_confidence,
        explanation=llm_explanation
    ))

    elapsed = (time.perf_counter() - start_time) * 1000

    return FirewallResponse(
        verdict=Verdict(llm_verdict),
        threat_category=_map_threat_category(llm_category),
        confidence=llm_confidence,
        explanation=llm_explanation,
        layers=layers,
        processing_time_ms=round(elapsed, 2),
        prompt_hash=_hash_prompt(prompt),
        blocked_by_layer="llm_classifier" if llm_triggered else None,
    )
