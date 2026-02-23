# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false
from __future__ import annotations

from pydantic import BaseModel

from pr_guardian.models import Diff, DiffFile, Hunk, Policy, Severity
from pr_guardian.rules.changelog_breaking import ChangelogBreakingRule


def _build_policy() -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["quality/changelog-breaking"],
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


def _build_diff_file(path: str, *, status: str = "modified", patch: str | None = "@@ -1 +1 @@\n-old\n+new") -> DiffFile:
    return DiffFile(
        path=path,
        status=status,  # type: ignore[arg-type]
        patch=patch,
        additions=1,
        deletions=1,
        hunks=[
            Hunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                lines=[("-", 1, None), ("+", None, 1)],
            )
        ],
    )


def test_breaking_keyword_without_changelog_or_version_triggers_finding() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(files=[_build_diff_file("src/users/public/client.ts")])

    findings = rule.execute(diff, _build_policy(), pr_title="feat!: remove user endpoint")

    assert len(findings) == 1
    assert findings[0].rule_id == "quality/changelog-breaking"
    assert findings[0].severity == Severity.ERROR


def test_breaking_change_in_pr_body_with_version_update_passes() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(
        files=[
            _build_diff_file("src/public/service.ts", status="removed", patch=None),
            _build_diff_file("packages/core/package.json", patch="@@ -1 +1 @@\n-1.2.3\n+2.0.0"),
        ]
    )

    findings = rule.execute(diff, _build_policy(), pr_body="This release has BREAKING CHANGE: remove service")

    assert findings == []


def test_packages_index_change_with_changelog_update_passes() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(
        files=[
            _build_diff_file("packages/auth/src/index.ts"),
            _build_diff_file("CHANGELOG.md", patch="@@ -1 +1 @@\n-old\n+breaking notes"),
        ]
    )

    findings = rule.execute(diff, _build_policy())

    assert findings == []


def test_api_root_change_without_changelog_triggers_finding() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(files=[_build_diff_file("api/users.ts")])

    findings = rule.execute(diff, _build_policy(), pr_title="feat: prune legacy endpoint")

    assert len(findings) == 1


def test_internal_api_folder_is_not_treated_as_public_api() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(files=[_build_diff_file("src/internal/api/helper.py")])

    findings = rule.execute(diff, _build_policy(), pr_title="refactor: internal cleanup")

    assert findings == []


class _RuleConfigPolicy(BaseModel):
    severity_overrides: dict[str, Severity]
    include: list[str]
    exclude: list[str]
    public_api_paths: list[str]
    changelog_files: list[str]


def test_custom_paths_and_severity_override_are_supported() -> None:
    rule = ChangelogBreakingRule()
    diff = Diff(files=[_build_diff_file("api/v1/users.py", status="removed", patch=None)])
    policy = _RuleConfigPolicy(
        severity_overrides={"quality/changelog-breaking": Severity.WARNING},
        include=["**/*"],
        exclude=[],
        public_api_paths=["api/v1/**"],
        changelog_files=["docs/releases/*.md"],
    )

    findings = rule.execute(diff, policy, pr_title="breaking change: remove v1 users api")  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
