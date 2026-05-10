"""
FastAPI Application Entry Point
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.models import FirewallRequest, FirewallResponse, HealthResponse
from app.firewall.detector import inspect
from app.logger.db import init_db, log_decision, get_today_stats
from app.firewall.llm_classifier import GROQ_MODEL

import os
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("Initialising SQLite database...")
    init_db()
    logger.info("Prompt Injection Firewall is ONLINE")
    yield
    logger.info("Shutting down firewall.")


app = FastAPI(
    title="Prompt Injection Firewall",
    description="3-layer detection pipeline: Regex → Heuristics → LLM (Groq free tier)",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/inspect", response_model=FirewallResponse, tags=["Firewall"])
async def inspect_prompt(request: FirewallRequest) -> FirewallResponse:
    """
    Inspect a prompt for injection / jailbreak attempts.

    Returns verdict (ALLOW/BLOCK), threat category, confidence, and layer breakdown.
    """
    try:
        response = inspect(
            prompt=request.prompt,
            session_id=request.session_id,
            context=request.context,
        )
        log_decision(response, session_id=request.session_id)
        return response
    except Exception as e:
        logger.error(f"Firewall error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Firewall error: {str(e)}")


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health() -> HealthResponse:
    """Health check with today's stats."""
    groq_key = os.getenv("GROQ_API_KEY", "")
    stats = get_today_stats()
    return HealthResponse(
        status="online",
        groq_available=bool(groq_key),
        total_requests_today=stats["total"],
        total_blocked_today=stats["blocked"],
        block_rate_today=stats["block_rate"],
    )


@app.get("/", tags=["System"])
async def root():
    return {
        "service": "Prompt Injection Firewall",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "inspect": "POST /inspect",
    }
