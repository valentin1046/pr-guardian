# pyright: reportMissingImports=false
from __future__ import annotations

from pydantic import BaseModel

from pr_guardian.models import Diff, DiffFile, Hunk, Policy, Severity
from pr_guardian.rules.lockfile_consistency import LockfileConsistencyRule


def _build_policy() -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["deps/lockfile-consistency"],
        severity_overrides={},
        llm_enabled=False,
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_max_context_tokens=1024,
        llm_budget_usd=0.0,
        deny_paths=[],
        max_changed_lines_for_autofix=50,
        require_evidence=True,
    )


def _build_diff_file(path: str) -> DiffFile:
    return DiffFile(
        path=path,
        status="modified",
        patch="@@ -1 +1 @@\n-old\n+new",
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


def test_manifest_changed_without_lockfile_produces_finding() -> None:
    rule = LockfileConsistencyRule()
    diff = Diff(files=[_build_diff_file("package.json")])

    findings = rule.execute(diff, _build_policy())

    assert len(findings) == 1
    assert findings[0].rule_id == "deps/lockfile-consistency"
    assert findings[0].severity == Severity.ERROR
    assert "package-lock.json" in findings[0].message


def test_manifest_and_lockfile_changed_returns_no_findings() -> None:
    rule = LockfileConsistencyRule()
    diff = Diff(files=[_build_diff_file("package.json"), _build_diff_file("pnpm-lock.yaml")])

    findings = rule.execute(diff, _build_policy())

    assert findings == []


def test_pyproject_accepts_any_supported_lockfile() -> None:
    rule = LockfileConsistencyRule()
    diff = Diff(files=[_build_diff_file("services/api/pyproject.toml"), _build_diff_file("services/api/poetry.lock")])

    findings = rule.execute(diff, _build_policy())

    assert findings == []


class _PolicyWithCustomMapping(BaseModel):
    lockfile_mappings: dict[str, list[str]]
    severity_overrides: dict[str, Severity]
    include: list[str]
    exclude: list[str]


def test_custom_mapping_detects_missing_custom_lockfile() -> None:
    rule = LockfileConsistencyRule()
    diff = Diff(files=[_build_diff_file("modules/custom-manifest.json")])
    policy = _PolicyWithCustomMapping(
        lockfile_mappings={"custom-manifest.json": ["custom.lock"]},
        severity_overrides={},
        include=["**/*"],
        exclude=[],
    )

    findings = rule.execute(diff, policy)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert "custom.lock" in findings[0].message
