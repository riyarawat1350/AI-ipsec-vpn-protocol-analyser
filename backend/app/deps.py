"""FastAPI dependency injection utilities."""

from fastapi import Header
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.config import settings
from backend.app.core.errors import UnauthorizedError
from backend.app.db.mongo import get_db as _get_mongo_db


def get_db() -> AsyncIOMotorDatabase:
    """Dependency returning the active MongoDB database handle."""
    return _get_mongo_db()


def verify_api_token(authorization: str | None = Header(default=None)) -> None:
    """Optional bearer token authentication check (FR-82, FR-83).

    If API_TOKEN is empty/None in settings, authentication is disabled.
    If API_TOKEN is configured, requires a matching 'Bearer <token>'.
    """
    if not settings.API_TOKEN:
        return

    if not authorization:
        raise UnauthorizedError("Missing Authorization header with Bearer token")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization header must follow 'Bearer <token>' format")

    token = parts[1]
    if token != settings.API_TOKEN:
        raise UnauthorizedError("Invalid bearer token")
