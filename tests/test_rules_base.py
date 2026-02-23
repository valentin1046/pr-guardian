# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUntypedBaseClass=false
from __future__ import annotations

from pr_guardian.models import Diff, Finding, Policy, Severity
from pr_guardian.rules.base import FindingFactory, Rule, RuleRegistry, match_glob_pattern, path_matches_any


class DummyRule(Rule):
    @property
    def rule_id(self) -> str:
        return "test/dummy"

    @property
    def title(self) -> str:
        return "Dummy Rule"

    @property
    def description(self) -> str:
        return "用于测试的规则"

    @property
    def default_severity(self) -> Severity:
        return Severity.WARNING

    def execute(self, diff: Diff, policy: Policy) -> list[Finding]:
        return []


def _make_policy(*, include: list[str] | None = None, exclude: list[str] | None = None) -> Policy:
    return Policy(
        gate=True,
        auto_fix=False,
        include=include or [],
        exclude=exclude or [],
        enabled_rules=["test/dummy"],
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


def test_rule_registry_register_and_get() -> None:
    registry = RuleRegistry()

    registry.register(DummyRule)

    assert registry.get("test/dummy") is DummyRule


def test_rule_registry_create_instance_returns_rule_object() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule)

    instance = registry.create_instance("test/dummy")

    assert isinstance(instance, DummyRule)


def test_match_glob_pattern_supports_recursive_wildcard() -> None:
    assert match_glob_pattern("src/pr_guardian/rules/base.py", "src/**/base.py")
    assert not match_glob_pattern("tests/test_rules_base.py", "src/**/base.py")


def test_path_matches_any_returns_true_when_any_pattern_matches() -> None:
    patterns = ["docs/**", "src/**/*.py"]

    assert path_matches_any("src/pr_guardian/rules/base.py", patterns)
    assert not path_matches_any("pyproject.toml", patterns)


def test_should_skip_file_respects_include_and_exclude() -> None:
    rule = DummyRule()
    policy = _make_policy(include=["src/**"], exclude=["src/**/legacy/**"])

    assert rule.should_skip_file("src/pr_guardian/rules/base.py", policy) is False
    assert rule.should_skip_file("tests/test_rules_base.py", policy) is True
    assert rule.should_skip_file("src/pr_guardian/legacy/rule.py", policy) is True


def test_finding_factory_generates_incremental_ids() -> None:
    rule = DummyRule()
    first = FindingFactory.create(rule, message="first", evidence=[])
    second = FindingFactory.create(rule, message="second", evidence=[])

    assert first.id == "test/dummy#1"
    assert second.id == "test/dummy#2"
    assert first.severity == Severity.WARNING
