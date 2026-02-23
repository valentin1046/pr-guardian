# pyright: reportMissingImports=false
from __future__ import annotations

from pr_guardian.models import Diff, DiffFile, Policy, Severity
from pr_guardian.rules.secrets_scan import SecretsScanRule


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


def _build_diff(path: str, patch: str) -> Diff:
    return Diff(
        files=[
            DiffFile(
                path=path,
                status="modified",
                patch=patch,
                additions=1,
                deletions=0,
                hunks=[],
            )
        ]
    )


def test_secrets_scan_detects_aws_access_key_on_added_line() -> None:
    patch = "\n".join(["@@ -1,1 +1,1 @@", '+aws_key = "AKIA1234567890ABCDEF"'])
    finding = SecretsScanRule().execute(_build_diff("src/auth.py", patch), _build_policy())

    assert len(finding) == 1
    assert finding[0].rule_id == "security/secrets-scan"
    assert finding[0].severity == Severity.ERROR


def test_secrets_scan_ignores_placeholder_values() -> None:
    patch = "\n".join(["@@ -0,0 +1,1 @@", '+api_key = "YOUR_KEY_HERE"'])

    findings = SecretsScanRule().execute(_build_diff("src/config.py", patch), _build_policy())

    assert findings == []


def test_secrets_scan_respects_allowlist_values() -> None:
    policy = _build_policy()
    policy.__dict__["allowlist"] = {"security/secrets-scan": ["AKIAIOSFODNN7EXAMPLE"]}
    patch = "\n".join(["@@ -0,0 +1,1 @@", '+aws_key = "AKIAIOSFODNN7EXAMPLE"'])

    findings = SecretsScanRule().execute(_build_diff("src/auth.py", patch), policy)

    assert findings == []


def test_secrets_scan_ignores_removed_lines() -> None:
    patch = "\n".join(["@@ -1,1 +1,1 @@", '-token = "sk-abcdefghijklmnopqrstuvwxyz1234"'])

    findings = SecretsScanRule().execute(_build_diff("src/client.py", patch), _build_policy())

    assert findings == []


def test_secrets_scan_detects_high_entropy_base64_value() -> None:
    patch = "\n".join(["@@ -0,0 +1,1 @@", '+secret = "QWxhZGRpbjpPcGVuU2VzYW1lVG9rZW5WYWx1ZTEyMzQ1Njc4OTA="'])

    findings = SecretsScanRule().execute(_build_diff("src/entropy.py", patch), _build_policy())

    assert len(findings) >= 1
    assert any("高熵 Base64" in item.message for item in findings)
