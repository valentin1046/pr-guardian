# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false
from __future__ import annotations

from pr_guardian.models import Diff, DiffFile, Policy, Severity
from pr_guardian.rules.affected_tests import AffectedTestsRule


def _make_policy() -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["monorepo/affected-tests"],
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


def _make_diff(*paths: str) -> Diff:
    return Diff(
        files=[
            DiffFile(path=path, status="modified", patch=None, additions=1, deletions=0, hunks=[])
            for path in paths
        ]
    )


def test_affected_tests_generates_warning_when_test_not_declared() -> None:
    rule = AffectedTestsRule()
    policy = _make_policy()
    diff = _make_diff("src/app/service.py")

    findings = rule.execute(diff, policy, pr_body="")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "monorepo/affected-tests"
    assert finding.severity == Severity.WARNING
    assert "tests/**/*.py" in finding.message


def test_affected_tests_skips_when_pr_body_declares_test_keyword() -> None:
    rule = AffectedTestsRule()
    policy = _make_policy()
    diff = _make_diff("src/app/service.py")

    findings = rule.execute(diff, policy, pr_body="Tests: 已运行 tests/unit/test_service.py")

    assert findings == []


def test_affected_tests_aggregates_multiple_suites() -> None:
    rule = AffectedTestsRule()
    policy = _make_policy()
    mappings = {
        "packages/*/src/**/*.py": [
            "packages/*/tests/**/*.py",
            "integration/tests/**/*.py",
        ]
    }
    diff = _make_diff("packages/payments/src/core/engine.py")

    findings = rule.execute(diff, policy, pr_body="", test_mappings=mappings)

    assert len(findings) == 1
    message = findings[0].message
    assert "packages/*/tests/**/*.py" in message
    assert "integration/tests/**/*.py" in message
