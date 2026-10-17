"""Backend configuration settings loaded from environment variables (SRS §16.2)."""

import json
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application configuration with type enforcement and environment loading."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core service settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # Database and file storage
    DATABASE_URL: str = "sqlite:///./data/ipsecscope.db"
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "ipsecscope"
    UPLOAD_DIR: str = "./data/uploads"
    REPORT_DIR: str = "./data/reports"

    # Processing bounds
    MAX_UPLOAD_MB: int = 200
    MAX_PACKETS: int = 2_000_000
    ANALYSIS_TIMEOUT_S: int = 300
    WORKERS: int = 2
    RETENTION_DAYS: int = 7

    # Security & CORS
    API_TOKEN: str | None = None
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:8080", "http://127.0.0.1:5173"]

    # Analysis Defaults
    DEFAULT_POLICY: str = "nist_default"
    ML_MODEL_PATH: str = "analyzer/ml/models/ike_iforest.joblib"

    # LLM Settings
    LLM_PROVIDER: str = "none"
    LLM_BASE_URL: str | None = None
    LLM_API_KEY: str | None = None
    LLM_MODEL: str | None = None
    LLM_SEND_REAL_IPS: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        """Support comma-separated or JSON list for CORS origins."""
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return [str(item) for item in v]
        return ["*"]

    def ensure_directories(self) -> None:
        """Ensure upload and report directories exist."""
        Path(self.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.REPORT_DIR).mkdir(parents=True, exist_ok=True)


settings = AppSettings()
settings.ensure_directories()
