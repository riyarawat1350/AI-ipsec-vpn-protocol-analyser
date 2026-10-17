"""API tests for FastAPI app shell, security headers, auth on/off, and error envelopes (TASK-004)."""

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.deps import verify_api_token
from backend.app.main import create_app


@pytest.fixture
def client():
    """TestClient fixture with default settings."""
    app = create_app()
    return TestClient(app)


@pytest.mark.api
def test_health_endpoint(client):
    """Verify health endpoint returns 200 and security headers."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}

    # Security headers verification
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


@pytest.mark.api
def test_capabilities_endpoints(client):
    """Verify capabilities endpoints at root and under /api/v1."""
    for path in ("/capabilities", "/api/v1/capabilities"):
        response = client.get(path)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        item = data[0]
        assert "id" in item
        assert "feature" in item
        assert "status" in item
        assert "priority" in item


@pytest.mark.api
def test_404_error_envelope(client):
    """Verify 404 responses conform to standard error envelope (SRS §9.1)."""
    response = client.get("/api/v1/non_existent_resource")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "message" in data["error"]


@pytest.mark.api
def test_422_validation_error_envelope():
    """Verify 422 validation errors conform to standard error envelope."""
    app = create_app()
    router = APIRouter()

    @router.get("/test-validation")
    def sample_endpoint(limit: int):
        return {"limit": limit}

    app.include_router(router)
    client = TestClient(app)

    response = client.get("/test-validation?limit=not_an_int")
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "errors" in data["error"]["details"]


@pytest.mark.api
def test_auth_on_and_off(monkeypatch):
    """Verify authentication dependency behavior when auth is disabled vs enabled."""
    app = create_app()
    router = APIRouter()

    @router.get("/protected", dependencies=[Depends(verify_api_token)])
    def protected_route():
        return {"secret": "accessed"}

    app.include_router(router)

    # 1. Auth OFF (API_TOKEN is None/empty)
    monkeypatch.setattr(settings, "API_TOKEN", None)
    client = TestClient(app)
    res_off = client.get("/protected")
    assert res_off.status_code == 200
    assert res_off.json() == {"secret": "accessed"}

    # 2. Auth ON
    monkeypatch.setattr(settings, "API_TOKEN", "super_secret_token_123")

    # 2a. Missing token -> 401
    res_no_auth = client.get("/protected")
    assert res_no_auth.status_code == 401
    err_data = res_no_auth.json()
    assert err_data["error"]["code"] == "UNAUTHORIZED"

    # 2b. Invalid token -> 401
    res_bad_auth = client.get("/protected", headers={"Authorization": "Bearer wrong_token"})
    assert res_bad_auth.status_code == 401
    assert res_bad_auth.json()["error"]["code"] == "UNAUTHORIZED"

    # 2c. Valid token -> 200
    res_good_auth = client.get(
        "/protected", headers={"Authorization": "Bearer super_secret_token_123"}
    )
    assert res_good_auth.status_code == 200
    assert res_good_auth.json() == {"secret": "accessed"}
