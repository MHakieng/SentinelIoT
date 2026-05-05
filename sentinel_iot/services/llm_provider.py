import json
import os
from abc import ABC, abstractmethod
from urllib import error, request


class ProviderConfigError(RuntimeError):
    """Raised when the LLM provider is not configured."""


class ProviderExecutionError(RuntimeError):
    """Raised when the LLM provider call fails."""


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate a text response for the given prompts."""


class OpenAIChatProvider(LLMProvider):
    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1/chat/completions",
        timeout_seconds: int = 20,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise ProviderExecutionError(f"LLM provider returned HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise ProviderExecutionError(f"LLM provider could not be reached: {exc.reason}") from exc
        except Exception as exc:  # pragma: no cover - defensive network handling
            raise ProviderExecutionError(f"Unexpected LLM provider error: {exc}") from exc

        choices = raw.get("choices") or []
        if not choices:
            raise ProviderExecutionError("LLM provider returned no choices.")

        message = choices[0].get("message") or {}
        content = message.get("content")
        if not content:
            raise ProviderExecutionError("LLM provider returned an empty message.")
        return content


class GeminiGenerateContentProvider(LLMProvider):
    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta/models",
        timeout_seconds: int = 20,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "system_instruction": {
                "parts": [
                    {
                        "text": system_prompt,
                    }
                ]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": user_prompt,
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "response_mime_type": "application/json",
            },
        }
        data = json.dumps(payload).encode("utf-8")
        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
        req = request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise ProviderExecutionError(f"LLM provider returned HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise ProviderExecutionError(f"LLM provider could not be reached: {exc.reason}") from exc
        except Exception as exc:  # pragma: no cover - defensive network handling
            raise ProviderExecutionError(f"Unexpected LLM provider error: {exc}") from exc

        candidates = raw.get("candidates") or []
        if not candidates:
            prompt_feedback = raw.get("promptFeedback") or {}
            block_reason = prompt_feedback.get("blockReason")
            if block_reason:
                raise ProviderExecutionError(f"LLM provider blocked the prompt: {block_reason}")
            raise ProviderExecutionError("LLM provider returned no candidates.")

        content = candidates[0].get("content") or {}
        parts = content.get("parts") or []
        if not parts:
            raise ProviderExecutionError("LLM provider returned an empty message.")

        text_chunks = [part.get("text", "") for part in parts if part.get("text")]
        content_text = "".join(text_chunks).strip()
        if not content_text:
            raise ProviderExecutionError("LLM provider returned an empty message.")
        return content_text


class UnavailableLLMProvider(LLMProvider):
    def __init__(self, message: str):
        self.message = message

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        raise ProviderConfigError(self.message)


def build_llm_provider_from_env() -> LLMProvider:
    provider_name = os.getenv("SENTINEL_LLM_PROVIDER", "openai").strip().lower()
    api_key = os.getenv("SENTINEL_LLM_API_KEY", "").strip()
    model = os.getenv("SENTINEL_LLM_MODEL", "").strip()
    default_base_url = (
        "https://generativelanguage.googleapis.com/v1beta/models"
        if provider_name == "gemini"
        else "https://api.openai.com/v1/chat/completions"
    )
    base_url = os.getenv("SENTINEL_LLM_BASE_URL", default_base_url).strip()
    timeout_seconds = int(os.getenv("SENTINEL_LLM_TIMEOUT_SECONDS", "20"))

    if not api_key or not model:
        raise ProviderConfigError(
            "LLM provider is not configured. Set SENTINEL_LLM_API_KEY and SENTINEL_LLM_MODEL."
        )

    if provider_name == "openai":
        return OpenAIChatProvider(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )

    if provider_name == "gemini":
        return GeminiGenerateContentProvider(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )

    if provider_name not in {"openai", "gemini"}:
        raise ProviderConfigError(
            f"Unsupported LLM provider '{provider_name}'. Supported providers: 'openai', 'gemini'."
        )
    raise ProviderConfigError(f"Unsupported LLM provider '{provider_name}'.")


def get_llm_provider_status_from_env() -> dict:
    """Return non-secret LLM configuration status for health/status endpoints."""
    provider_name = os.getenv("SENTINEL_LLM_PROVIDER", "openai").strip().lower() or "openai"
    model = os.getenv("SENTINEL_LLM_MODEL", "").strip()
    api_key_present = bool(os.getenv("SENTINEL_LLM_API_KEY", "").strip())
    supported = provider_name in {"openai", "gemini"}

    enabled = supported and api_key_present and bool(model)
    missing = []
    if not api_key_present:
        missing.append("SENTINEL_LLM_API_KEY")
    if not model:
        missing.append("SENTINEL_LLM_MODEL")
    if not supported:
        missing.append("supported SENTINEL_LLM_PROVIDER")

    return {
        "enabled": enabled,
        "provider": provider_name,
        "model": model or None,
        "supported": supported,
        "missing": missing,
    }
