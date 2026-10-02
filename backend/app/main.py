import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.middleware import CorrelationIdMiddleware
from common.logging_utils import configure_logging

settings = get_settings()
configure_logging(service="backend", level=settings.log_level)
logger = logging.getLogger("backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("backend starting up")
    yield
    logger.info("backend shutting down")


app = FastAPI(
    title="CyberStream API",
    version="0.1.0",
    description="Security analytics API for the CyberStream Big Data platform.",
    lifespan=lifespan,
)

app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
register_exception_handlers(app)


@app.get("/health", tags=["health"])
def health() -> dict:
    """Liveness probe for the API process itself (not downstream services)."""
    return {"status": "ok", "service": "backend"}


@app.get("/api/health", tags=["health"])
def api_health() -> dict:
    """
    Readiness probe. Reports "unknown" for dependencies until Phase 7 wires
    real Kafka/Postgres connectivity checks here - it does not claim a
    dependency is healthy without checking it.
    """
    return {
        "status": "ok",
        "service": "backend",
        "dependencies": {
            "postgres": "not_yet_checked",
            "kafka": "not_yet_checked",
        },
    }

# Routers for events/alerts/incidents/kafka/spark/benchmarks are added in Phase 7,
# each as app.include_router(...) here - keeping route wiring centralized.
