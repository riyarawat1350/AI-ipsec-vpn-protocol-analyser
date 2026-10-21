"""Tests for report generation and preview endpoints (HTML, PDF, JSON, CSV)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_db():
    db = MagicMock()
    analyses_col = MagicMock()
    uploads_col = MagicMock()
    findings_col = MagicMock()
    sessions_col = MagicMock()
    flows_col = MagicMock()
    recs_col = MagicMock()
    reports_col = MagicMock()

    analyses_col.find_one = AsyncMock(return_value={
        "_id": "test_analysis_12345",
        "status": "completed",
        "upload_id": "upload_123",
        "posture": {"score": 85.0, "grade": "B"},
        "narrative": {"report_card": {"what_we_saw": "Observed test capture", "how_worried": "Low risk"}},
    })
    uploads_col.find_one = AsyncMock(return_value={
        "_id": "upload_123",
        "original_filename": "test.pcap",
        "sha256": "abcdef1234567890abcdef1234567890",
        "packet_count": 10,
    })

    def make_cursor(*args, **kwargs):
        c = MagicMock()
        c.sort = MagicMock(return_value=c)
        c.to_list = AsyncMock(return_value=[])
        return c

    findings_col.find = MagicMock(side_effect=make_cursor)
    sessions_col.find = MagicMock(side_effect=make_cursor)
    flows_col.find = MagicMock(side_effect=make_cursor)
    recs_col.find = MagicMock(side_effect=make_cursor)
    reports_col.update_one = AsyncMock()

    cols = {
        "analyses": analyses_col,
        "uploads": uploads_col,
        "findings": findings_col,
        "ike_sessions": sessions_col,
        "ipsec_flows": flows_col,
        "recommendations": recs_col,
        "reports": reports_col,
    }
    db.__getitem__.side_effect = lambda k: cols.get(k, MagicMock())
    return db


@pytest.mark.api
def test_report_preview_endpoints_html_and_pdf(mock_db, tmp_path):
    with (
        patch("backend.app.db.mongo.connect_db", new_callable=AsyncMock),
        patch("backend.app.db.mongo.close_db", new_callable=AsyncMock),
        patch("backend.app.config.settings.REPORT_DIR", str(tmp_path)),
    ):
        from backend.app.db.mongo import get_db
        from backend.app.main import create_app

        app = create_app()
        app.dependency_overrides[get_db] = lambda: mock_db

        with TestClient(app) as client:
            # 1. Preview HTML
            html_res = client.get("/api/v1/analyses/test_analysis_12345/report?format=html")
            assert html_res.status_code == 200, f"HTML preview failed: {html_res.text}"
            assert "text/html" in html_res.headers["content-type"]
            assert html_res.headers.get("X-Frame-Options") == "SAMEORIGIN"
            assert "IPsecScope Assessment Report" in html_res.text

            # 2. Preview / Download PDF
            pdf_res = client.get("/api/v1/analyses/test_analysis_12345/report?format=pdf")
            assert pdf_res.status_code == 200, f"PDF preview failed: {pdf_res.text}"
            assert "application/pdf" in pdf_res.headers["content-type"]
            assert pdf_res.headers.get("X-Frame-Options") == "SAMEORIGIN"
            assert pdf_res.content.startswith(b"%PDF-")

            # 3. Security headers check on non-report endpoint
            health_res = client.get("/health")
            assert health_res.status_code == 200
            assert health_res.headers.get("X-Frame-Options") == "DENY"
