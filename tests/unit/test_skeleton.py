"""Skeleton verification test."""

import pytest

import analyzer
from backend.app.main import app


@pytest.mark.unit
def test_analyzer_package_version():
    """Verify analyzer package is importable and has version."""
    assert analyzer.__version__ == "0.1.0"


@pytest.mark.unit
def test_backend_app_instance():
    """Verify FastAPI backend instance is created."""
    assert app.title == "IPsecScope API"
