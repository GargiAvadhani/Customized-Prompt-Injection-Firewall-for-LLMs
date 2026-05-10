from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    ROLE_OVERRIDE = "ROLE_OVERRIDE"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class FirewallRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000, description="The user prompt to inspect")
    session_id: Optional[str] = Field(default=None, description="Optional session identifier for tracking")
    context: Optional[str] = Field(default=None, description="Optional system context for better classification")


class LayerResult(BaseModel):
    layer_name: str
    triggered: bool
    confidence: float  # 0.0 to 1.0
    matched_rules: List[str] = []
    score: Optional[float] = None
    explanation: Optional[str] = None


class FirewallResponse(BaseModel):
    verdict: Verdict
    threat_category: ThreatCategory
    confidence: float  # 0.0 to 1.0
    explanation: str
    layers: List[LayerResult]
    processing_time_ms: float
    prompt_hash: str  # SHA-256 first 16 chars (for logging without storing raw prompt)
    blocked_by_layer: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    status: str
    groq_available: bool
    total_requests_today: int
    total_blocked_today: int
    block_rate_today: float
