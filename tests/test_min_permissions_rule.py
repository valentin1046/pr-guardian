# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false
from __future__ import annotations

from pr_guardian.models import Diff, DiffFile, Policy, Severity
from pr_guardian.rules.min_permissions import MinPermissionsRule


def _build_policy() -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=["**/*"],
        exclude=[],
        enabled_rules=["ci/min-permissions"],
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


def _build_workflow_diff(path: str, lines: list[str]) -> Diff:
    patch_lines = [f"@@ -0,0 +1,{len(lines)} @@"]
    patch_lines.extend(f"+{line}" for line in lines)
    patch = "\n".join(patch_lines)

    return Diff(
        files=[
            DiffFile(
                path=path,
                status="added",
                patch=patch,
                additions=len(lines),
                deletions=0,
                hunks=[],
            )
        ]
    )


def test_missing_permissions_creates_finding() -> None:
    rule = MinPermissionsRule()
    workflow_lines = [
        "name: CI",
        "on: [push]",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
    ]

    findings = rule.execute(_build_workflow_diff(".github/workflows/ci.yml", workflow_lines), _build_policy())

    assert len(findings) == 1
    assert findings[0].rule_id == "ci/min-permissions"
    assert findings[0].severity == Severity.ERROR
    assert findings[0].evidence[0].line == 3
    assert findings[0].evidence[0].snippet == "jobs:"


def test_write_all_permissions_are_detected_with_exact_line() -> None:
    rule = MinPermissionsRule()
    workflow_lines = [
        "name: CI",
        "on: [push]",
        "permissions: write-all",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
    ]

    findings = rule.execute(_build_workflow_diff(".github/workflows/ci.yml", workflow_lines), _build_policy())

    assert len(findings) == 1
    assert "write-all" in findings[0].message
    assert findings[0].evidence[0].line == 3
    assert findings[0].evidence[0].snippet == "permissions: write-all"


def test_allowlist_allows_contents_write_for_specific_workflow() -> None:
    rule = MinPermissionsRule()
    policy = _build_policy()
    policy.__dict__["allowlist"] = {
        "permission_allowlist": [
            {
                "path": ".github/workflows/release.yml",
                "scopes": ["contents: write", "packages: write"],
            }
        ]
    }
    workflow_lines = [
        "name: Release",
        "on: [push]",
        "permissions:",
        "  contents: write",
        "jobs:",
        "  release:",
        "    runs-on: ubuntu-latest",
    ]

    findings = rule.execute(_build_workflow_diff(".github/workflows/release.yml", workflow_lines), policy)

    assert findings == []


def test_id_token_write_is_detected_on_job_permissions_line() -> None:
    rule = MinPermissionsRule()
    workflow_lines = [
        "name: Deploy",
        "on: [workflow_dispatch]",
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    permissions:",
        "      id-token: write",
        "    steps:",
        "      - uses: actions/checkout@v4",
    ]

    findings = rule.execute(_build_workflow_diff(".github/workflows/deploy.yml", workflow_lines), _build_policy())

    assert len(findings) == 1
    assert "id-token: write" in findings[0].message
    assert findings[0].evidence[0].line == 7
    assert findings[0].evidence[0].snippet == "      id-token: write"


def test_check_permissions_signature_and_write_all_detection() -> None:
    rule = MinPermissionsRule()
    workflow = {
        "name": "CI",
        "permissions": "write-all",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}},
    }

    findings = rule._check_permissions(workflow, ".github/workflows/ci.yml")

    assert len(findings) == 1
    assert "write-all" in findings[0].message
