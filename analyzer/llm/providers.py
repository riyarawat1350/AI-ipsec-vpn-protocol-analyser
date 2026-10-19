"""LLM Providers interface and implementations (TASK-039 / SRS §11.5 / §16.2).

Supports openai_compat (Groq, OpenAI, LocalAI, vLLM, etc.) and fake provider for unit tests.
Security rule: API keys must NEVER be logged or leaked into error messages.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)


class LLMProvider(Protocol):
    """Protocol for LLM narrative providers."""

    @property
    def model_name(self) -> str:
        ...

    def generate(self, prompt: str, system_prompt: str, json_mode: bool = True) -> str | None:
        """Generate response from provider. Returns None on failure."""
        ...


class OpenAICompatProvider:
    """OpenAI-compatible chat completion provider (Groq, OpenAI, etc.)."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        raw_url = (base_url or os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        if not raw_url.endswith("/chat/completions"):
            self.endpoint = f"{raw_url}/chat/completions"
        else:
            self.endpoint = raw_url

        self._api_key = api_key or os.getenv("LLM_API_KEY") or ""
        self.model = model or os.getenv("LLM_MODEL") or "llama-3.3-70b-versatile"
        self.timeout_seconds = timeout_seconds

    @property
    def model_name(self) -> str:
        return self.model

    def _sanitize_error(self, err_msg: str) -> str:
        """Strip API key or authorization tokens from any error message."""
        if not self._api_key:
            return err_msg
        return err_msg.replace(self._api_key, "[REDACTED]")

    def generate(self, prompt: str, system_prompt: str, json_mode: bool = True) -> str | None:
        """Call chat completions with 20s timeout and 1 retry on 429/5xx."""
        if not self._api_key:
            logger.warning("LLM generation skipped: LLM_API_KEY is not configured.")
            return None

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        for attempt in range(1, 3):  # Max 2 attempts (initial + 1 retry)
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    resp = client.post(self.endpoint, headers=headers, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices") or []
                    if choices:
                        return choices[0].get("message", {}).get("content", "")
                    return None

                # If 404 model_not_found, auto-detect available chat model on endpoint
                if resp.status_code == 404 and "model_not_found" in resp.text and attempt == 1:
                    logger.info("Configured model '%s' not found on endpoint; checking available models...", self.model)
                    try:
                        models_endpoint = self.endpoint.replace("/chat/completions", "/models")
                        m_resp = httpx.get(models_endpoint, headers=headers, timeout=self.timeout_seconds)
                        if m_resp.status_code == 200:
                            data_models = [m["id"] for m in m_resp.json().get("data", []) if not m["id"].startswith("whisper") and not "guard" in m["id"]]
                            if data_models:
                                chosen = "openai/gpt-oss-120b" if "openai/gpt-oss-120b" in data_models else data_models[0]
                                self.model = chosen
                                payload["model"] = chosen
                                logger.info("Retrying chat completion with available model: %s", chosen)
                                continue
                    except Exception as mex:
                        logger.warning("Failed querying models: %s", mex)

                # On 429 rate limit or 5xx server errors, retry once
                if resp.status_code in (429, 500, 502, 503, 504) and attempt == 1:
                    logger.info("LLM provider returned status %d; retrying once in 1.0s...", resp.status_code)
                    time.sleep(1.0)
                    continue

                logger.warning(
                    "LLM provider failed with HTTP %d: %s",
                    resp.status_code,
                    self._sanitize_error(resp.text[:200]),
                )
                return None

            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt == 1:
                    logger.info("LLM request timeout/transport error; retrying once...")
                    time.sleep(1.0)
                    continue
                logger.warning("LLM request failed after retry: %s", self._sanitize_error(str(exc)))
                return None
            except Exception as exc:
                logger.warning("Unexpected error during LLM generation: %s", self._sanitize_error(str(exc)))
                return None

        return None


class FakeLLMProvider:
    """Mock provider for unit tests and determinism verification (TC-056, TC-057)."""

    def __init__(self, canned_response: str | None = None) -> None:
        self.canned_response = canned_response or "{}"
        self.last_prompt: str | None = None
        self.last_system_prompt: str | None = None
        self.call_count: int = 0
        self.model = "fake-model-v1"

    @property
    def model_name(self) -> str:
        return self.model

    def generate(self, prompt: str, system_prompt: str, json_mode: bool = True) -> str | None:
        self.call_count += 1
        self.last_prompt = prompt
        self.last_system_prompt = system_prompt
        return self.canned_response


def get_llm_provider(
    provider_name: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> LLMProvider | None:
    """Instantiate configured LLM provider or return None if disabled."""
    name = (provider_name or os.getenv("LLM_PROVIDER") or "none").strip().lower()
    if name in ("none", "", "disabled"):
        return None

    if name == "openai_compat":
        return OpenAICompatProvider(base_url=base_url, api_key=api_key, model=model)

    logger.warning("Unsupported LLM_PROVIDER '%s'; falling back to none.", name)
    return None
