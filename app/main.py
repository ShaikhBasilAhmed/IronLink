"""IronLink pin-distribution API.

Endpoints:
  GET /get-pins   -> signed pin set (served from in-memory cache; CDN-cacheable)
  GET /healthz    -> liveness (process up)
  GET /readyz     -> readiness (a valid signed response is available to serve)
  GET /metrics    -> Prometheus metrics (if METRICS_ENABLED)

No request body, no nonce. Replay protection is handled out of band.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.cache import SignedResponseCache, run_refresher
from app.config import get_settings
from app.deps import get_signer, get_vault_client
from app.logging_conf import configure_logging
from app.metrics import CACHE_AGE, READY, REQUESTS
from app.models import ErrorResponse
from app.security import SecurityHeadersMiddleware, client_ip

settings = get_settings()
configure_logging(settings.LOG_LEVEL)
logger = logging.getLogger("ironlink")

limiter = Limiter(key_func=client_ip, default_limits=[settings.RATE_LIMIT])
_state: dict = {}


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting", extra={"addr": settings.VAULT_ADDR, "host": settings.PIN_HOST})
    vault = get_vault_client()
    signer = get_signer()  # loads private key from Vault; fails fast if unavailable
    cache = SignedResponseCache(vault, signer, settings.PIN_HOST, settings.PIN_STALE_GRACE)
    await cache.refresh()  # warm before accepting traffic
    if not cache.ready:
        # Do not serve if we have nothing valid to serve.
        raise RuntimeError("STARTUP FAILED: could not build an initial signed pin set from Vault")
    stop = asyncio.Event()
    task = asyncio.create_task(run_refresher(cache, settings.PIN_REFRESH_INTERVAL, stop))
    _state["cache"] = cache
    logger.info("ready")
    try:
        yield
    finally:
        stop.set()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=5)


app = FastAPI(title="IronLink Pin Service", docs_url=None, redoc_url=None, lifespan=lifespan)
app.state.limiter = limiter
app.add_middleware(SecurityHeadersMiddleware)


def _err(status: int, code: str, msg: str) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content=ErrorResponse(error=msg, code=code).model_dump())


@app.exception_handler(RateLimitExceeded)
async def _rl(request: Request, exc: RateLimitExceeded):
    r = _err(429, "RATE_LIMITED", "too many requests")
    r.headers["Retry-After"] = "60"
    return r


@app.exception_handler(RequestValidationError)
async def _val(request: Request, exc: RequestValidationError):
    return _err(400, "BAD_REQUEST", "invalid request")


@app.get("/get-pins")
@limiter.limit(settings.RATE_LIMIT)
async def get_pins(request: Request):
    cache: SignedResponseCache = _state.get("cache")
    snap = cache.snapshot() if cache else None
    if snap is None:
        REQUESTS.labels(result="unavailable").inc()
        return _err(503, "PINS_UNAVAILABLE", "pins temporarily unavailable")
    body, etag = snap
    CACHE_AGE.set(cache.age_seconds())

    cache_control = (
        f"public, max-age={settings.CDN_MAX_AGE}, "
        f"stale-while-revalidate={settings.CDN_STALE_WHILE_REVALIDATE}"
    )
    # Conditional request support (CDN / client revalidation)
    if request.headers.get("if-none-match") == etag:
        REQUESTS.labels(result="not_modified").inc()
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": cache_control})

    REQUESTS.labels(result="ok").inc()
    return Response(
        content=body,
        media_type="application/json",
        headers={"ETag": etag, "Cache-Control": cache_control},
    )


@app.get("/healthz")
async def healthz():
    # Liveness: process is up and serving. Does NOT touch Vault.
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    cache: SignedResponseCache = _state.get("cache")
    ready = bool(cache and cache.ready)
    READY.set(1 if ready else 0)
    if ready:
        return {"status": "ready", "ageSeconds": round(cache.age_seconds(), 1)}
    return JSONResponse(status_code=503, content={"status": "not_ready"})


if settings.METRICS_ENABLED:
    @app.get("/metrics")
    async def metrics():
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
