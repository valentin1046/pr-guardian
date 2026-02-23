# pyright: reportMissingImports=false
from __future__ import annotations

from typing import Any

from pr_guardian.models import Evidence, Finding, Policy, Severity
from pr_guardian.report.github_reporter import GitHubReporter


class FakeGitHubClient:
    def __init__(self) -> None:
        self.repo = "octo/repo"
        self.check_run_calls: list[dict[str, Any]] = []
        self.review_calls: list[dict[str, Any]] = []
        self.issue_comment_creations: list[dict[str, Any]] = []
        self.issue_comment_updates: list[dict[str, Any]] = []
        self.existing_issue_comments: list[dict[str, Any]] = []
        self.existing_review_comments: list[dict[str, Any]] = []

    def create_check_run(
        self,
        name: str,
        head_sha: str,
        status: str,
        conclusion: str | None,
        output: dict[str, Any],
        annotations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "conclusion": conclusion,
            "output": output,
            "annotations": annotations,
        }
        self.check_run_calls.append(payload)
        return {"id": 1, "status": status, "conclusion": conclusion}

    def create_review(
        self,
        pr_number: int,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]],
        event: str = "COMMENT",
    ) -> dict[str, Any]:
        payload = {
            "pr_number": pr_number,
            "commit_id": commit_id,
            "body": body,
            "comments": comments,
            "event": event,
        }
        self.review_calls.append(payload)
        return {"id": 9, "state": "COMMENTED", "comments": comments}

    def create_pr_comment(self, pr_number: int, body: str) -> dict[str, Any]:
        payload = {"pr_number": pr_number, "body": body}
        self.issue_comment_creations.append(payload)
        return {"id": 123, "body": body}

    def list_pr_comments(self, pr_number: int) -> list[dict[str, Any]]:
        _ = pr_number
        return self.existing_issue_comments

    def _request(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        expected_statuses: set[int] | None = None,
    ) -> Any:
        _ = params, expected_statuses
        if method == "GET" and endpoint.endswith("/pulls/7/comments"):
            return self.existing_review_comments
        if method == "PATCH" and endpoint.startswith("/repos/octo/repo/issues/comments/"):
            if json is None:
                raise AssertionError("json 不能为空")
            self.issue_comment_updates.append({"endpoint": endpoint, "body": json.get("body", "")})
            return {"id": 456, "body": json.get("body", "")}
        raise AssertionError(f"未处理请求: {method} {endpoint}")


def _build_policy() -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["security/secrets-scan"],
        severity_overrides={},
        llm_enabled=False,
        llm_provider="openai",
        llm_model="gpt-4o-mini",
        llm_max_context_tokens=2048,
        llm_budget_usd=0.0,
        deny_paths=[],
        max_changed_lines_for_autofix=200,
        require_evidence=True,
    )


def _build_finding(rule_id: str, severity: Severity, file: str = "src/a.py", line: int = 3) -> Finding:
    return Finding(
        id=f"{rule_id}-{severity.value}-{line}",
        rule_id=rule_id,
        title="规则标题",
        severity=severity,
        message="发现问题",
        evidence=[Evidence(file=file, line=line, snippet="bad()")],
        tags=["tag"],
        confidence=0.9,
    )


def test_group_helpers_work_as_expected() -> None:
    reporter = GitHubReporter(client=FakeGitHubClient(), policy=_build_policy())
    findings = [
        _build_finding("security/secrets-scan", Severity.ERROR),
        _build_finding("ci/min-permissions", Severity.WARNING, line=8),
    ]

    grouped_by_severity = reporter._group_by_severity(findings)
    grouped_by_category = reporter._group_by_category(findings)

    assert len(grouped_by_severity[Severity.ERROR]) == 1
    assert len(grouped_by_severity[Severity.WARNING]) == 1
    assert len(grouped_by_category["Security"]) == 1
    assert len(grouped_by_category["CI"]) == 1


def test_publish_check_run_marks_failure_when_has_error_and_limits_annotations() -> None:
    fake_client = FakeGitHubClient()
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())
    findings = [_build_finding("security/secrets-scan", Severity.ERROR, line=idx + 1) for idx in range(60)]

    result = reporter._publish_check_run("head-sha", findings)

    assert result["conclusion"] == "failure"
    assert len(fake_client.check_run_calls) == 1
    payload = fake_client.check_run_calls[0]
    assert payload["output"]["title"] == "PR Guardian Results"
    assert len(payload["annotations"]) == 50


def test_publish_check_run_marks_success_without_error() -> None:
    fake_client = FakeGitHubClient()
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())

    result = reporter._publish_check_run("head-sha", [_build_finding("docs/spell", Severity.INFO)])

    assert result["conclusion"] == "success"


def test_publish_review_comments_creates_inline_comments() -> None:
    fake_client = FakeGitHubClient()
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())
    findings = [
        _build_finding("security/secrets-scan", Severity.ERROR, file="src/auth.py", line=11),
        _build_finding("ci/min-permissions", Severity.WARNING, file=".github/workflows/ci.yml", line=4),
    ]

    result = reporter._publish_review_comments(pr_number=7, commit_id="commit-sha", findings=findings)

    assert result["comment_count"] == 2
    assert fake_client.review_calls[0]["comments"][0]["path"] == "src/auth.py"
    assert fake_client.review_calls[0]["comments"][0]["line"] == 11


def test_publish_review_comments_uses_fingerprint_for_dedup() -> None:
    fake_client = FakeGitHubClient()
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())
    finding = _build_finding("security/secrets-scan", Severity.ERROR, file="src/auth.py", line=10)
    fingerprint = reporter._get_fingerprint(finding)
    fake_client.existing_review_comments = [{"body": f"历史评论\n<!-- pr-guardian:fingerprint={fingerprint} -->"}]

    result = reporter._publish_review_comments(pr_number=7, commit_id="commit-sha", findings=[finding])

    assert result["comment_count"] == 0
    assert fake_client.review_calls == []


def test_publish_summary_comment_updates_existing_comment() -> None:
    fake_client = FakeGitHubClient()
    fake_client.existing_issue_comments = [
        {"id": 99, "body": "<!-- pr-guardian:summary -->\n旧内容"},
    ]
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())
    findings = [
        _build_finding("security/secrets-scan", Severity.ERROR),
        _build_finding("docs/readme", Severity.WARNING, line=4),
    ]

    result = reporter._publish_summary_comment(pr_number=7, findings=findings)

    assert result["updated"] is True
    assert len(fake_client.issue_comment_updates) == 1
    assert "## Security" in fake_client.issue_comment_updates[0]["body"]
    assert "## Docs" in fake_client.issue_comment_updates[0]["body"]


def test_report_findings_returns_three_channel_results() -> None:
    fake_client = FakeGitHubClient()
    reporter = GitHubReporter(client=fake_client, policy=_build_policy())

    result = reporter.report_findings(
        pr_number=7,
        head_sha="head-sha",
        findings=[_build_finding("security/secrets-scan", Severity.ERROR)],
        commit_id="commit-sha",
    )

    assert set(result.keys()) == {"check_run", "review", "summary"}
