# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportImplicitOverride=false
from __future__ import annotations

from importlib import import_module
from typing import cast

from ..models import Diff, Finding, Policy, Severity
from .base import FindingFactory, Rule, RuleRegistry

registry = RuleRegistry()


def _build_placeholder_rule(target_rule_id: str) -> type[Rule]:
    class PlaceholderRule(Rule):
        @property
        def rule_id(self) -> str:
            return target_rule_id

        @property
        def title(self) -> str:
            return target_rule_id

        @property
        def description(self) -> str:
            return f"占位规则: {target_rule_id}"

        @property
        def default_severity(self) -> Severity:
            return Severity.INFO

        def execute(self, diff: Diff, policy: Policy) -> list[Finding]:
            return []

    return PlaceholderRule


def _register_rule(rule_id: str, module_path: str, class_name: str) -> None:
    try:
        module = import_module(module_path)
        rule_class = cast(object, getattr(module, class_name))
    except (ModuleNotFoundError, AttributeError):
        registry.register(_build_placeholder_rule(rule_id))
        return

    if not isinstance(rule_class, type) or not issubclass(rule_class, Rule):
        registry.register(_build_placeholder_rule(rule_id))
        return

    registry.register(rule_class)


_register_rule("security/secrets-scan", "pr_guardian.rules.security.secrets_scan", "SecretsScanRule")
_register_rule("deps/lockfile-consistency", "pr_guardian.rules.lockfile_consistency", "LockfileConsistencyRule")
_register_rule("monorepo/affected-tests", "pr_guardian.rules.affected_tests", "AffectedTestsRule")
_register_rule("ci/min-permissions", "pr_guardian.rules.min_permissions", "MinPermissionsRule")
_register_rule("quality/changelog-breaking", "pr_guardian.rules.quality.changelog_breaking", "ChangelogBreakingRule")


__all__ = ["Rule", "FindingFactory", "RuleRegistry", "registry"]
