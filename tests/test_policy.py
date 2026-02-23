from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from pydantic import ValidationError

POLICY_MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "pr_guardian" / "policy.py"
policy_spec = importlib.util.spec_from_file_location("policy_under_test", POLICY_MODULE_PATH)
if policy_spec is None or policy_spec.loader is None:
    raise RuntimeError("无法加载策略模块")
policy_module = importlib.util.module_from_spec(policy_spec)
policy_spec.loader.exec_module(policy_module)

DEFAULT_CONFIG = policy_module.DEFAULT_CONFIG
PolicyLoader = policy_module.PolicyLoader
Severity = policy_module.Severity
_apply_defaults = policy_module._apply_defaults
validate_policy = policy_module.validate_policy


def _write_yaml(path: Path, content: str) -> None:
    _ = path.write_text(content, encoding="utf-8")


def test_apply_defaults_keeps_default_values() -> None:
    merged = _apply_defaults({"mode": {"gate": False}})

    assert merged["mode"]["gate"] is False
    assert merged["mode"]["auto_fix"] is DEFAULT_CONFIG["mode"]["auto_fix"]
    assert merged["llm"]["strategy"]["rubric"] == DEFAULT_CONFIG["llm"]["strategy"]["rubric"]


def test_loader_inherits_defaults_from_partial_file(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
mode:
  gate: false
rules:
  enabled:
    - security/secrets-scan
""".strip(),
    )

    policy = PolicyLoader().load(config_path)

    assert policy.gate is False
    assert policy.auto_fix is False
    assert policy.llm.provider == "openai"


def test_loader_uses_current_directory_when_path_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(config_path, "mode:\n  gate: false\n")
    monkeypatch.chdir(tmp_path)

    policy = PolicyLoader().load()

    assert policy.gate is False


def test_loader_rejects_invalid_field_type(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
llm:
  max_context_tokens: wrong
""".strip(),
    )

    with pytest.raises(ValidationError):
        PolicyLoader().load(config_path)


def test_validate_policy_rejects_unknown_provider(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
rules:
  enabled:
    - security/secrets-scan
llm:
  provider: unknown
""".strip(),
    )

    policy = PolicyLoader().load(config_path)
    errors = validate_policy(policy)

    assert any("provider" in err for err in errors)


def test_validate_policy_rejects_unknown_rule_in_severity_overrides(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
rules:
  enabled:
    - security/secrets-scan
  severity_overrides:
    unknown/rule: warning
""".strip(),
    )

    policy = PolicyLoader().load(config_path)
    errors = validate_policy(policy)

    assert any("severity_overrides" in err for err in errors)


def test_validate_policy_detects_include_exclude_conflict(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
scope:
  include:
    - src/**
  exclude:
    - src/**
""".strip(),
    )

    policy = PolicyLoader().load(config_path)
    errors = validate_policy(policy)

    assert any("include" in err and "exclude" in err for err in errors)


def test_loader_supports_disabling_rules(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
rules:
  enabled: []
  severity_overrides:
    security/secrets-scan: info
""".strip(),
    )

    policy = PolicyLoader().load(config_path)

    assert policy.enabled_rules == []
    assert policy.severity_overrides["security/secrets-scan"] == Severity.INFO


def test_loader_supports_lockfile_mappings(tmp_path: Path) -> None:
    config_path = tmp_path / ".pr-guardian.yml"
    _write_yaml(
        config_path,
        """
rules:
  lockfile_mappings:
    custom-manifest.json:
      - custom.lock
""".strip(),
    )

    policy = PolicyLoader().load(config_path)

    assert policy.lockfile_mappings == {"custom-manifest.json": ["custom.lock"]}
