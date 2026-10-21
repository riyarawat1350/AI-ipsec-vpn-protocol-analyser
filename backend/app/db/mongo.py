"""MongoDB connection and collection management.

Replaces SQLAlchemy/SQLite with Motor (async MongoDB driver).
Collections mirror the original SRS §10 tables.

Decision DEC-005: User requested full MongoDB migration; Motor (async)
chosen for FastAPI compatibility. All documents use _id = UUID string.
"""

from __future__ import annotations

import logging
import re

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

logger = logging.getLogger(__name__)

# Module-level client (lazy init)
_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def mask_mongo_url(url: str) -> str:
    """Mask credentials in MongoDB connection string: mongodb+srv://user:pass@host -> mongodb+srv://user:***@host."""
    return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:***@", url)


async def connect_db(mongo_url: str, db_name: str = "ipsecscope") -> AsyncIOMotorDatabase:
    """Open the Motor connection pool and ensure indexes exist."""
    global _client, _db

    _client = AsyncIOMotorClient(mongo_url)
    _db = _client[db_name]

    await _ensure_indexes(_db)
    logger.info("MongoDB connected: %s / %s", mask_mongo_url(mongo_url), db_name)
    return _db


async def close_db() -> None:
    """Close the Motor connection pool."""
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None
        logger.info("MongoDB connection closed.")


def get_db() -> AsyncIOMotorDatabase:
    """Return the active database handle (raises if not connected)."""
    if _db is None:
        raise RuntimeError("MongoDB not connected. Call connect_db() first.")
    return _db


# ---------------------------------------------------------------------------
# Collection name constants
# ---------------------------------------------------------------------------
class Collections:
    UPLOADS = "uploads"
    ANALYSES = "analyses"
    IKE_SESSIONS = "ike_sessions"
    IKE_MESSAGES = "ike_messages"
    FINDINGS = "findings"
    IPSEC_FLOWS = "ipsec_flows"
    RECOMMENDATIONS = "recommendations"
    AUDIT_LOG = "audit_log"


# ---------------------------------------------------------------------------
# Index creation
# ---------------------------------------------------------------------------
async def _ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """Create all required MongoDB indexes (idempotent)."""

    # uploads
    await db[Collections.UPLOADS].create_indexes([
        IndexModel([("sha256", ASCENDING)], unique=True),
        IndexModel([("created_at", DESCENDING)]),
    ])

    # analyses
    await db[Collections.ANALYSES].create_indexes([
        IndexModel([("upload_id", ASCENDING)]),
        IndexModel([("status", ASCENDING)]),
        IndexModel([("created_at", DESCENDING)]),
        IndexModel([("upload_id", ASCENDING), ("status", ASCENDING)]),
    ])

    # ike_sessions
    await db[Collections.IKE_SESSIONS].create_indexes([
        IndexModel([("analysis_id", ASCENDING)]),
        IndexModel([("spi_i", ASCENDING)]),
        IndexModel([("initiator.ip", ASCENDING)]),
        IndexModel([("responder.ip", ASCENDING)]),
    ])

    # ike_messages
    await db[Collections.IKE_MESSAGES].create_indexes([
        IndexModel([("analysis_id", ASCENDING)]),
        IndexModel([("session_id", ASCENDING)]),
        IndexModel([("pkt_no", ASCENDING)]),
    ])

    # findings
    await db[Collections.FINDINGS].create_indexes([
        IndexModel([("analysis_id", ASCENDING)]),
        IndexModel([("severity", ASCENDING)]),
        IndexModel([("risk_score", DESCENDING)]),
        IndexModel([("rule_id", ASCENDING)]),
        IndexModel([("fingerprint", ASCENDING)]),
    ])

    # ipsec_flows
    await db[Collections.IPSEC_FLOWS].create_indexes([
        IndexModel([("analysis_id", ASCENDING)]),
        IndexModel([("spi", ASCENDING)]),
        IndexModel([("src", ASCENDING), ("dst", ASCENDING)]),
    ])

    # recommendations
    await db[Collections.RECOMMENDATIONS].create_indexes([
        IndexModel([("analysis_id", ASCENDING)]),
        IndexModel([("priority", ASCENDING)]),
    ])

    # audit_log
    await db[Collections.AUDIT_LOG].create_indexes([
        IndexModel([("timestamp", DESCENDING)]),
        IndexModel([("analysis_id", ASCENDING)]),
    ])

    logger.info("MongoDB indexes ensured.")
