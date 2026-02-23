from __future__ import annotations

import asyncio
import importlib
import json
import sys
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any, cast

import httpx
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "src"))
providers_module = importlib.import_module("pr_guardian.llm.providers")

GLMClient = providers_module.GLMClient
KimiClient = providers_module.KimiClient
MiniMaxClient = providers_module.MiniMaxClient
OpenAIClient = providers_module.OpenAIClient


class ReviewResult(BaseModel):
    risk: str
    score: int


def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    return asyncio.run(coro)


def test_openai_provider_supports_mock_transport_and_parses_schema() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["response_format"] == {"type": "json_object"}
        return httpx.Response(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({"risk": "low", "score": 2}),
                        }
                    }
                ]
            },
        )

    client = OpenAIClient(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
    )

    parsed, findings = _run_async(
        client.generate_structured(
            model="gpt-4o",
            messages=[{"role": "user", "content": "review this"}],
            schema=ReviewResult,
        )
    )
    _run_async(client.aclose())

    assert parsed == ReviewResult(risk="low", score=2)
    assert findings == []


def test_provider_retries_three_times_with_exponential_backoff() -> None:
    call_count = 0
    slept_durations: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept_durations.append(seconds)

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(status_code=500, json={"error": {"message": "transient"}})
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": {"content": '{"risk":"medium","score":5}'}}]},
        )

    client = OpenAIClient(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
        sleep_func=fake_sleep,
    )

    parsed, findings = _run_async(
        client.generate_structured(
            model="gpt-4o",
            messages=[{"role": "user", "content": "review"}],
            schema=ReviewResult,
        )
    )
    _run_async(client.aclose())

    assert parsed is not None
    assert findings == []
    assert call_count == 3
    assert slept_durations == [0.5, 1.0]


def test_schema_validation_failure_returns_error_finding() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": {"content": '{"risk":1,"score":"x"}'}}]},
        )

    client = OpenAIClient(api_key="test-key", transport=httpx.MockTransport(handler))

    parsed, findings = _run_async(
        client.generate_structured(
            model="gpt-4o",
            messages=[{"role": "user", "content": "review"}],
            schema=ReviewResult,
        )
    )
    _run_async(client.aclose())

    assert parsed is None
    assert len(findings) == 1
    assert findings[0].rule_id == "llm/schema-validation"


def test_all_providers_share_timeout_and_token_estimation() -> None:
    providers = [
        OpenAIClient(api_key="key", transport=httpx.MockTransport(_mock_ok_handler())),
        GLMClient(api_key="key", transport=httpx.MockTransport(_mock_ok_handler())),
        MiniMaxClient(api_key="key", transport=httpx.MockTransport(_mock_ok_handler())),
        KimiClient(api_key="key", transport=httpx.MockTransport(_mock_ok_handler())),
    ]

    for provider in providers:
        assert provider.client.timeout.read == 30.0
        token_count = provider.estimate_tokens([{"role": "user", "content": "abcd"}])
        assert token_count >= 1
        _run_async(provider.aclose())


def test_http_error_returns_unified_error_finding() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=401, json={"error": {"message": "bad key"}})

    client = KimiClient(api_key="bad-key", transport=httpx.MockTransport(handler))

    parsed, findings = _run_async(
        client.generate_structured(
            model="moonshot-v1-8k",
            messages=[{"role": "user", "content": "review"}],
            schema=ReviewResult,
        )
    )
    _run_async(client.aclose())

    assert parsed is None
    assert len(findings) == 1
    assert findings[0].rule_id == "llm/provider-error"
    assert findings[0].severity.value == "error"


def _mock_ok_handler() -> Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]]:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": {"content": '{"risk":"low","score":1}'}}]},
        )

    return cast(Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]], handler)
