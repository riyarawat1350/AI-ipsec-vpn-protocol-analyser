"""Structured logging configuration for backend."""

import logging
import sys

from backend.app.config import settings


def setup_logging() -> None:
    """Initialize standard structured logging."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


logger = logging.getLogger("ipsecscope")
