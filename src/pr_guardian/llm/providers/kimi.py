# pyright: reportMissingImports=false
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import httpx

from pr_guardian.llm.providers.openai import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BASE_DELAY_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    OpenAICompatibleClient,
)


class KimiClient(OpenAICompatibleClient):
    provider_name = "kimi"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.moonshot.cn/v1",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_base_delay_seconds: float = DEFAULT_RETRY_BASE_DELAY_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep_func: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            use_response_format=True,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_delay_seconds=retry_base_delay_seconds,
            transport=transport,
            sleep_func=sleep_func,
        )


__all__ = ["KimiClient"]
