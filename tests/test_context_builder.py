# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false
from __future__ import annotations

import json

from pr_guardian.context_builder import ContextBuilder, _should_include_file, detect_language
from pr_guardian.models import Diff, DiffFile, Evidence, Finding, Hunk, Policy, Severity


def _build_policy(max_tokens: int = 3000) -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["security/secrets-scan", "docs/changelog"],
        severity_overrides={},
        llm_enabled=True,
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_max_context_tokens=max_tokens,
        llm_budget_usd=1.0,
        deny_paths=[],
        max_changed_lines_for_autofix=50,
        require_evidence=True,
    )


def _build_file(path: str, patch: str, additions: int = 1, deletions: int = 0) -> DiffFile:
    return DiffFile(
        path=path,
        status="modified",
        patch=patch,
        additions=additions,
        deletions=deletions,
        hunks=[
            Hunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                lines=[("+", None, 1)],
            )
        ],
    )


def _build_finding(rule_id: str, file_path: str, tags: list[str]) -> Finding:
    return Finding(
        id=f"id-{rule_id}",
        rule_id=rule_id,
        title="title",
        severity=Severity.ERROR,
        message="message",
        evidence=[Evidence(file=file_path, line=1, snippet="x")],
        tags=tags,
        confidence=0.9,
    )


def test_detect_language_supports_common_suffix() -> None:
    assert detect_language("src/main.py") == "python"
    assert detect_language("infra/workflow.yml") == "yaml"
    assert detect_language("unknown.ext") == "text"


def test_redact_secrets_masks_api_key_bearer_email_private_key() -> None:
    builder = ContextBuilder(_build_policy())
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    text = "\n".join(
        [
            "token=sk-abcdefghijklmn",
            "public=pk-12345678abcdefgh",
            "Authorization: Bearer abc.def.ghi",
            "mail=user@example.com",
            private_key,
        ]
    )

    redacted = builder.redact_secrets(text)

    assert "sk-abcdefghijklmn" not in redacted
    assert "pk-12345678abcdefgh" not in redacted
    assert "Bearer abc.def.ghi" not in redacted
    assert "user@example.com" not in redacted
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert redacted.count("[REDACTED]") >= 4


def test_estimate_tokens_handles_chinese_and_english() -> None:
    builder = ContextBuilder(_build_policy())

    assert builder.estimate_tokens("中文") == 2
    assert builder.estimate_tokens("abcd") == 1
    assert builder.estimate_tokens("中文abcd") == 3


def test_crop_file_context_limits_max_lines_and_keeps_hotspots() -> None:
    builder = ContextBuilder(_build_policy())
    patch = "\n".join(f"+line {index}" for index in range(250))
    diff_file = _build_file("src/service.py", patch, additions=250)

    cropped = builder.crop_file_context(diff_file, max_lines=200)

    assert cropped["path"] == "src/service.py"
    assert cropped["language"] == "python"
    assert len(cropped["patch"].splitlines()) == 200
    assert len(cropped["hotspots"]) == 1
    assert cropped["hotspots"][0]["line_start"] == 1


def test_should_include_file_depends_on_findings_evidence() -> None:
    changed_file = _build_file("src/a.py", "+a")
    finding = _build_finding("security/secrets-scan", "src/a.py", ["security"])

    assert _should_include_file(changed_file, [finding]) is True

    other_finding = _build_finding("docs/changelog", "docs/changelog.md", ["docs"])
    assert _should_include_file(changed_file, [other_finding]) is False


def test_build_context_respects_budget_and_prioritizes_security() -> None:
    policy = _build_policy(max_tokens=500)
    builder = ContextBuilder(policy)

    security_file = _build_file("src/auth.py", "\n".join("+x" for _ in range(40)), additions=40)
    docs_file = _build_file("docs/readme.md", "\n".join("+y" for _ in range(260)), additions=260)
    diff = Diff(files=[docs_file, security_file])

    findings = [
        _build_finding("docs/changelog", "docs/readme.md", ["docs"]),
        _build_finding("security/secrets-scan", "src/auth.py", ["security"]),
    ]

    payload = builder.build_context(diff, findings)
    payload_tokens = builder.estimate_tokens(json.dumps(payload, ensure_ascii=False))

    assert payload_tokens <= policy.llm_max_context_tokens
    assert payload["changed_files"]
    assert payload["changed_files"][0]["path"] == "src/auth.py"


def test_build_context_includes_all_files_when_findings_empty() -> None:
    builder = ContextBuilder(_build_policy(max_tokens=1000))
    file_a = _build_file("src/a.py", "+a")
    file_b = _build_file("src/b.ts", "+b")

    payload = builder.build_context(Diff(files=[file_a, file_b]), findings=[])

    assert [item["path"] for item in payload["changed_files"]] == ["src/a.py", "src/b.ts"]
