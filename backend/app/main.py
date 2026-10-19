"""FastAPI application entrypoint and app factory for IPsecScope."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.analyses import router as analyses_router
from backend.app.api.v1.compare import router as compare_router
from backend.app.api.v1.esp import router as esp_router
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.ike import router as ike_router
from backend.app.api.v1.meta import router as meta_router
from backend.app.api.v1.policies import router as policies_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.config import settings
from backend.app.core.errors import register_exception_handlers
from backend.app.core.logging import setup_logging
from backend.app.core.security import SecurityHeadersMiddleware
from backend.app.db.mongo import close_db, connect_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: connect MongoDB on startup, close on shutdown."""
    setup_logging()
    settings.ensure_directories()
    await connect_db(settings.MONGODB_URL, settings.MONGODB_DB_NAME)
    yield
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="IPsecScope API",
        version="0.1.0",
        description="API for AI-Assisted IPsec VPN Protocol Analyzer and Security Assessment Framework",
        lifespan=lifespan,
    )

    # 1. Security Headers
    app.add_middleware(SecurityHeadersMiddleware)

    # 2. CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 3. Standard Error Envelope Handlers
    register_exception_handlers(app)

    # 4. Include Routers
    app.include_router(meta_router, prefix="/api/v1")
    app.include_router(analyses_router, prefix="/api/v1")
    app.include_router(findings_router, prefix="/api/v1")
    app.include_router(ike_router, prefix="/api/v1")
    app.include_router(esp_router, prefix="/api/v1")
    app.include_router(compare_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(policies_router, prefix="/api/v1")

    # Root convenience endpoints (SRS §9.1 endpoints 23 & 24)
    @app.get("/health", tags=["Root"])
    def root_health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/capabilities", tags=["Root"])
    def root_capabilities():
        from analyzer.capabilities import get_capabilities
        return get_capabilities()

    return app


app = create_app()
