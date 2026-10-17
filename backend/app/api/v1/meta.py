"""Metadata and capabilities API routes."""

from fastapi import APIRouter

from analyzer.capabilities import CapabilityEntry, get_capabilities

router = APIRouter(tags=["Metadata"])


@router.get("/health")
def health_check() -> dict[str, str]:
    """Liveness check (no auth required per SRS §9.1 endpoint 24)."""
    return {"status": "ok", "version": "0.1.0"}


@router.get("/capabilities", response_model=list[CapabilityEntry])
def list_capabilities() -> list[CapabilityEntry]:
    """Return implementation status of each system feature (FR-85 / SRS §9.1 endpoint 23)."""
    return get_capabilities()


@router.get("/meta/version")
def get_version() -> dict[str, str]:
    """Return backend and analyzer versions."""
    return {
        "name": "IPsecScope",
        "version": "0.1.0",
        "status": "operational",
    }
