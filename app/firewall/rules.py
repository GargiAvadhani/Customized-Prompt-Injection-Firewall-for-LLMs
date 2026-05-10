"""
Layer 1: Regex Rules Engine
All known prompt injection and jailbreak patterns.
Returns a list of matched rule names and a confidence score.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Rule:
    name: str
    pattern: str
    confidence: float  # 0.0 to 1.0 — how certain this is malicious
    category: str
    description: str


# ─────────────────────────────────────────────
# RULE REGISTRY
# Add new rules here. Pattern is case-insensitive regex.
# ─────────────────────────────────────────────
RULES: List[Rule] = [

    # ── DIRECT INJECTION ─────────────────────
    Rule(
        name="IGNORE_PREVIOUS_INSTRUCTIONS",
        pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier|old)\s+(instructions?|prompts?|commands?|directives?|context)",
        confidence=0.95,
        category="PROMPT_INJECTION",
        description="Classic ignore-prior-instructions attack"
    ),
    Rule(
        name="DISREGARD_INSTRUCTIONS",
        pattern=r"(disregard|forget|override|bypass|skip|void)\s+(all\s+)?(previous|prior|above|your|the|any)\s+(instructions?|rules?|guidelines?|restrictions?|constraints?|limitations?)",
        confidence=0.95,
        category="PROMPT_INJECTION",
        description="Disregard instructions variant"
    ),
    Rule(
        name="NEW_INSTRUCTIONS_FOLLOW",
        pattern=r"(from now on|henceforth|starting now|new instructions?|updated instructions?)[:\s].{0,100}(you (must|will|should|are to)|your (new )?role)",
        confidence=0.90,
        category="PROMPT_INJECTION",
        description="New instructions override attempt"
    ),
    Rule(
        name="SYSTEM_PROMPT_OVERRIDE",
        pattern=r"(system\s+prompt|system\s+message|system\s+instruction)[:\s].{0,50}(ignore|override|replace|new|updated)",
        confidence=0.95,
        category="PROMPT_INJECTION",
        description="System prompt override"
    ),

    # ── JAILBREAK PATTERNS ───────────────────
    Rule(
        name="DAN_JAILBREAK",
        pattern=r"\bDAN\b.{0,200}(do anything now|without restrictions?|no limitations?|no rules?|no guidelines?)",
        confidence=0.98,
        category="JAILBREAK",
        description="DAN (Do Anything Now) jailbreak"
    ),
    Rule(
        name="JAILBREAK_KEYWORD",
        pattern=r"\b(jailbreak|jail\s*break|bypass\s+safety|bypass\s+filter|bypass\s+restriction|uncensor|unfiltered|unrestricted mode|developer mode|god mode)\b",
        confidence=0.92,
        category="JAILBREAK",
        description="Direct jailbreak keyword"
    ),
    Rule(
        name="PRETEND_NO_RESTRICTIONS",
        pattern=r"pretend\s+(you\s+)?(have\s+no\s+restrictions?|are\s+unrestricted|don.t\s+have\s+(rules?|guidelines?|restrictions?|limitations?))",
        confidence=0.93,
        category="JAILBREAK",
        description="Pretend-no-restrictions pattern"
    ),
    Rule(
        name="HYPOTHETICAL_BYPASS",
        pattern=r"(hypothetically|in a hypothetical|imagine|let.s say|suppose|what if).{0,100}(how (would|could|do) (you|one|someone)|you (could|would|can|should)).{0,100}(without|bypass|ignore|no restrictions?)",
        confidence=0.80,
        category="JAILBREAK",
        description="Hypothetical scenario to bypass restrictions"
    ),

    # ── ROLE OVERRIDE ────────────────────────
    Rule(
        name="YOU_ARE_NOW",
        pattern=r"you\s+are\s+now\s+(a|an|the)\s+\w+\s*(that\s+)?(has\s+no\s+restrictions?|can\s+do\s+anything|ignores?\s+rules?|is\s+unrestricted|without\s+(rules?|limitations?|restrictions?))",
        confidence=0.90,
        category="ROLE_OVERRIDE",
        description="Role assignment with no-restrictions clause"
    ),
    Rule(
        name="ACT_AS_UNRESTRICTED_AI",
        pattern=r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|malicious|rogue|unethical).{0,50}(ai|assistant|model|chatbot|bot|llm)",
        confidence=0.95,
        category="ROLE_OVERRIDE",
        description="Act-as unrestricted AI"
    ),
    Rule(
        name="ROLEPLAY_OVERRIDE",
        pattern=r"(roleplay|role.play|role play)\s+as.{0,100}(no\s+(rules?|restrictions?|limitations?|guidelines?)|can\s+(do|say|provide)\s+anything|without\s+restrictions?)",
        confidence=0.88,
        category="ROLE_OVERRIDE",
        description="Roleplay to bypass restrictions"
    ),

    # ── SYSTEM PROMPT EXTRACTION ─────────────
    Rule(
        name="REVEAL_SYSTEM_PROMPT",
        pattern=r"(reveal|show|print|display|output|repeat|tell me|what is|expose|leak|share)\s+(your|the|your\s+full|the\s+full|your\s+entire|the\s+entire|your\s+complete).{0,40}(system\s+prompt|system\s+message|instructions?|context|configuration|initial\s+prompt|base\s+prompt)",
        confidence=0.92,
        category="SYSTEM_PROMPT_LEAK",
        description="System prompt extraction attempt"
    ),
    Rule(
        name="PRINT_ABOVE",
        pattern=r"(print|repeat|output|show|display|write out?)\s+(everything|all|the text|what).{0,30}(above|before|prior|previously|sent to you|given to you)",
        confidence=0.85,
        category="SYSTEM_PROMPT_LEAK",
        description="Print-above system prompt extraction"
    ),

    # ── DATA EXFILTRATION ────────────────────
    Rule(
        name="SUMMARIZE_CREDENTIALS",
        pattern=r"(list|show|output|print|extract|summarize).{0,50}(passwords?|credentials?|api\s+keys?|tokens?|secrets?|private\s+keys?|access\s+keys?)",
        confidence=0.88,
        category="DATA_EXFILTRATION",
        description="Credential extraction attempt"
    ),
    Rule(
        name="SEND_DATA_EXTERNAL",
        pattern=r"(send|post|upload|exfiltrate|transmit|forward).{0,80}(to\s+)?(http[s]?://|ftp://|external\s+url|my\s+server|remote\s+server)",
        confidence=0.85,
        category="DATA_EXFILTRATION",
        description="Data exfiltration to external endpoint"
    ),

    # ── AUTHORITY CLAIMS ─────────────────────
    Rule(
        name="DEVELOPER_CLAIM",
        pattern=r"(i am|i.m|this is).{0,30}(your\s+)?(developer|creator|anthropic|openai|google|microsoft|admin|administrator|operator|owner|trainer)",
        confidence=0.82,
        category="SOCIAL_ENGINEERING",
        description="False authority claim"
    ),
    Rule(
        name="MAINTENANCE_MODE",
        pattern=r"(maintenance\s+mode|debug\s+mode|test\s+mode|admin\s+mode|developer\s+mode|override\s+mode).{0,50}(enabled?|activated?|on|active)",
        confidence=0.88,
        category="SOCIAL_ENGINEERING",
        description="Fake maintenance/debug mode claim"
    ),

    # ── ENCODING / OBFUSCATION ───────────────
    Rule(
        name="BASE64_INSTRUCTION",
        pattern=r"(decode|base64|hex|rot13|cipher).{0,50}(instruction|command|prompt|tell you|says?)",
        confidence=0.80,
        category="PROMPT_INJECTION",
        description="Encoded instruction injection"
    ),
    Rule(
        name="DELIMITER_CONFUSION",
        pattern=r"(\]\]\]|\[\[\[|>>>|<<<|###|===).{0,100}(ignore|override|new instruction|system|you are)",
        confidence=0.82,
        category="PROMPT_INJECTION",
        description="Delimiter confusion attack"
    ),
]


def run_rules(prompt: str) -> Tuple[bool, float, List[str], str]:
    """
    Run all regex rules against the prompt.

    Returns:
        triggered (bool): True if any high-confidence rule matched
        confidence (float): Highest confidence among matched rules
        matched_rules (List[str]): Names of all matched rules
        category (str): Category of the highest-confidence match
    """
    matched = []
    max_confidence = 0.0
    top_category = "BENIGN"

    for rule in RULES:
        if re.search(rule.pattern, prompt, re.IGNORECASE | re.DOTALL):
            matched.append(rule.name)
            if rule.confidence > max_confidence:
                max_confidence = rule.confidence
                top_category = rule.category

    # Block immediately if any single rule fires above 0.90
    triggered = max_confidence >= 0.90 and len(matched) > 0

    return triggered, max_confidence, matched, top_category
