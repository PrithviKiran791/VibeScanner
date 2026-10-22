"""`uvicorn vibeguard.api.main:app`"""

from typing import Annotated

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from vibeguard.api.deps import get_redis
from vibeguard.api.routes import router
from vibeguard.api.webhooks import router as webhook_router
from vibeguard.config import get_settings
from vibeguard.db.session import get_session

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",  # API responses carry scan data; never cache them
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="VibeGuard", version="0.4.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def harden(request: Request, call_next):
        # Refuse oversized bodies before reading them (Content-Length is required by our clients
        # and by GitHub; chunked uploads are rejected outright)
        if request.method in ("POST", "PUT", "PATCH"):
            length = request.headers.get("content-length")
            if length is None and request.headers.get("transfer-encoding"):
                return JSONResponse({"detail": "Length required"}, status_code=411)
            if length is not None and (
                not length.isdigit() or int(length) > settings.max_request_bytes
            ):
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.include_router(router)
    app.include_router(webhook_router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness: the process is up."""
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(
        session: Annotated[AsyncSession, Depends(get_session)],
        r: Annotated[aioredis.Redis, Depends(get_redis)],
    ) -> JSONResponse:
        """Readiness: PostgreSQL and Redis both answer. Used by the container healthcheck."""
        checks = {"database": "ok", "redis": "ok"}
        try:
            await session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            checks["database"] = "down"
        try:
            await r.ping()
        except RedisError:
            checks["redis"] = "down"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse(
            {"status": "ok" if ok else "degraded", **checks}, status_code=200 if ok else 503
        )

    return app


app = create_app()
