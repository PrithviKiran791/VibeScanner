"""`uvicorn vibeguard.api.main:app`"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vibeguard.api.routes import router
from vibeguard.config import get_settings


def create_app() -> FastAPI:
    app = FastAPI(title="VibeGuard", version="0.2.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type"],
    )
    app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
