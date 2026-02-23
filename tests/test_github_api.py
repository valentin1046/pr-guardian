# pyright: reportMissingImports=false
from __future__ import annotations

import time
from collections.abc import Callable

import httpx
import pytest

from pr_guardian.github_api import DiffFile, GitHubAPIClient, GitHubAPIError


def _build_client(handler: Callable[[httpx.Request], httpx.Response]) -> GitHubAPIClient:
    transport = httpx.MockTransport(handler)
    injected_client = httpx.Client(base_url="https://api.github.com", transport=transport)
    return GitHubAPIClient(token="test-token", repo="octo/repo", client=injected_client)


def test_get_pr_files_supports_pagination() -> None:
    request_counter = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        request_counter["count"] += 1
        page = int(request.url.params.get("page", "1"))
        if page == 1:
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "src/a.py",
                        "status": "modified",
                        "patch": "@@ -1 +1 @@",
                        "additions": 1,
                        "deletions": 1,
                    }
                ],
            )
        if page == 2:
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "src/b.py",
                        "status": "added",
                        "patch": "@@ -0,0 +1 @@",
                        "additions": 1,
                        "deletions": 0,
                    }
                ],
            )
        return httpx.Response(200, json=[])

    client = _build_client(handler)
    files = client.get_pr_files(pr_number=42)

    assert files == [
        DiffFile(filename="src/a.py", status="modified", patch="@@ -1 +1 @@", additions=1, deletions=1),
        DiffFile(filename="src/b.py", status="added", patch="@@ -0,0 +1 @@", additions=1, deletions=0),
    ]
    assert request_counter["count"] == 3


def test_get_pr_details_extracts_meta_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "title": "feat: add gate",
                "body": "body",
                "base": {"sha": "base-sha"},
                "head": {"sha": "head-sha"},
            },
        )

    client = _build_client(handler)
    details = client.get_pr_details(pr_number=7)

    assert details["title"] == "feat: add gate"
    assert details["body"] == "body"
    assert details["base_sha"] == "base-sha"
    assert details["head_sha"] == "head-sha"


def test_create_and_update_check_run() -> None:
    request_sequence: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_sequence.append((request.method, request.url.path))
        payload = request.read().decode("utf-8")
        if request.method == "POST":
            assert "quality-gate" in payload
            return httpx.Response(201, json={"id": 123, "status": "queued"})
        assert "completed" in payload
        return httpx.Response(200, json={"id": 123, "status": "completed", "conclusion": "success"})

    client = _build_client(handler)
    created = client.create_check_run(
        name="quality-gate",
        head_sha="abc",
        status="queued",
        conclusion=None,
        output={"title": "ok", "summary": "summary"},
        annotations=[],
    )
    updated = client.update_check_run(123, status="completed", conclusion="success")

    assert created["id"] == 123
    assert updated["conclusion"] == "success"
    assert request_sequence == [
        ("POST", "/repos/octo/repo/check-runs"),
        ("PATCH", "/repos/octo/repo/check-runs/123"),
    ]


def test_create_review_and_comments_apis() -> None:
    comment_list_calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/reviews"):
            return httpx.Response(200, json={"id": 90, "state": "COMMENTED"})
        if request.url.path.endswith("/issues/3/comments") and request.method == "POST":
            return httpx.Response(201, json={"id": 91, "body": "summary"})
        comment_list_calls["count"] += 1
        if comment_list_calls["count"] == 1:
            return httpx.Response(200, json=[{"id": 1, "body": "old"}])
        return httpx.Response(200, json=[])

    client = _build_client(handler)
    review = client.create_review(
        pr_number=3,
        commit_id="sha",
        body="review body",
        comments=[{"path": "src/a.py", "line": 1, "body": "nit"}],
    )
    comment = client.create_pr_comment(pr_number=3, body="summary")
    comments = client.list_pr_comments(pr_number=3)

    assert review["id"] == 90
    assert comment["id"] == 91
    assert comments[0]["id"] == 1


def test_retry_rate_limit_uses_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    request_counter = {"count": 0}
    sleep_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_counter["count"] += 1
        if request_counter["count"] == 1:
            return httpx.Response(
                403,
                headers={"Retry-After": "2", "X-RateLimit-Remaining": "0"},
                json={"message": "rate limit"},
            )
        return httpx.Response(200, json={"title": "ok", "body": "b", "base": {"sha": "b"}, "head": {"sha": "h"}})

    monkeypatch.setattr(time, "sleep", lambda seconds: sleep_calls.append(seconds))
    client = _build_client(handler)

    details = client.get_pr_details(pr_number=4)

    assert details["title"] == "ok"
    assert request_counter["count"] == 2
    assert sleep_calls == [2.0]


def test_non_retryable_4xx_raises_context() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not found"})

    client = _build_client(handler)

    with pytest.raises(GitHubAPIError, match="status=404"):
        client.get_pr_details(pr_number=404)
