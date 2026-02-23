# pyright: reportMissingImports=false
from __future__ import annotations

import hashlib
import math
import re

from pr_guardian.models import Diff, DiffFile, Finding, Policy, Severity
from pr_guardian.rules.base import Evidence, FindingFactory, Rule, RuleRegistry


class SecretsScanRule(Rule):
    RULE_ID = "security/secrets-scan"
    RULE_TITLE = "硬编码密钥扫描"
    RULE_DESCRIPTION = "扫描 PR 新增行中的硬编码密钥与高熵可疑字符串。"
    RULE_TAGS = ["security", "secrets"]

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def title(self) -> str:
        return self.RULE_TITLE

    @property
    def description(self) -> str:
        return self.RULE_DESCRIPTION

    @property
    def default_severity(self) -> Severity:
        return Severity.ERROR

    @property
    def tags(self) -> list[str]:
        return self.RULE_TAGS.copy()

    ENTROPY_THRESHOLD = 3.8
    MIN_BASE64_LENGTH = 20
    MIN_HEX_LENGTH = 32

    PATTERNS: dict[str, tuple[re.Pattern[str], bool]] = {
        "aws_access_key": (re.compile(r"AKIA[0-9A-Z]{16}"), False),
        "aws_secret": (re.compile(r"[0-9a-zA-Z/+]{40}"), True),
        "github_token": (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), False),
        "openai_key": (re.compile(r"sk-[a-zA-Z0-9]{20,}"), False),
        "slack_token": (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}"), False),
        "generic_api_key": (
            re.compile(r"(?:api[_-]?key|apikey)[\s]*[=:][\s]*['\"][a-zA-Z0-9_\-]{16,}['\"]", re.IGNORECASE),
            False,
        ),
        "private_key": (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), False),
    }

    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
    HEX_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,}\b")
    ALLOWLIST = ["AKIAIOSFODNN7EXAMPLE"]
    PLACEHOLDER_KEYWORDS = {
        "xxx",
        "xxxx",
        "***",
        "changeme",
        "change_me",
        "replace_me",
        "your_key_here",
        "your_api_key",
        "your-token-here",
        "dummy",
        "example",
        "sample",
    }

    def execute(self, diff: Diff, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        severity = policy.severity_overrides.get(self.rule_id, self.default_severity)
        allowlist = self._resolve_allowlist(policy)

        for diff_file in diff.files:
            if self.should_skip_file(diff_file.path, policy):
                continue
            if not diff_file.patch:
                continue

            for line_number, content in self._iter_added_lines(diff_file):
                findings.extend(self._scan_known_patterns(diff_file, line_number, content, severity, allowlist))
                findings.extend(self._scan_entropy(diff_file, line_number, content, severity, allowlist))

        return findings

    def _scan_known_patterns(
        self,
        diff_file: DiffFile,
        line_number: int,
        content: str,
        severity: Severity,
        allowlist: list[str],
    ) -> list[Finding]:
        results: list[Finding] = []
        for pattern_name, (pattern, needs_entropy) in self.PATTERNS.items():
            for match in pattern.finditer(content):
                secret_text = match.group(0)
                if self._is_allowlisted(secret_text, allowlist):
                    continue
                if self._is_placeholder(secret_text):
                    continue
                if needs_entropy and self._calculate_entropy(secret_text) < self.ENTROPY_THRESHOLD:
                    continue
                evidence = [Evidence(file=diff_file.path, line=line_number, snippet=content.strip())]
                results.append(
                    FindingFactory.create(
                        self,
                        message=f"检测到疑似硬编码密钥 ({pattern_name})。",
                        evidence=evidence,
                        severity=severity,
                    )
                )
        return results

    def _scan_entropy(
        self,
        diff_file: DiffFile,
        line_number: int,
        content: str,
        severity: Severity,
        allowlist: list[str],
    ) -> list[Finding]:
        results: list[Finding] = []
        for candidate in self.BASE64_PATTERN.findall(content):
            if len(candidate) < self.MIN_BASE64_LENGTH:
                continue
            if self._matches_known_pattern(candidate):
                continue
            if self._is_allowlisted(candidate, allowlist) or self._is_placeholder(candidate):
                continue
            if self._calculate_entropy(candidate) < self.ENTROPY_THRESHOLD:
                continue
            evidence = [Evidence(file=diff_file.path, line=line_number, snippet=content.strip())]
            results.append(
                FindingFactory.create(
                    self,
                    message="检测到高熵 Base64 字符串，疑似密钥。",
                    evidence=evidence,
                    severity=severity,
                )
            )

        for candidate in self.HEX_PATTERN.findall(content):
            if len(candidate) < self.MIN_HEX_LENGTH:
                continue
            if self._matches_known_pattern(candidate):
                continue
            if self._is_allowlisted(candidate, allowlist) or self._is_placeholder(candidate):
                continue
            if self._calculate_entropy(candidate) < self.ENTROPY_THRESHOLD:
                continue
            fingerprint = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:10]
            evidence = [Evidence(file=diff_file.path, line=line_number, snippet=content.strip())]
            results.append(
                FindingFactory.create(
                    self,
                    message=f"检测到高熵十六进制字符串，疑似密钥 (fp:{fingerprint})。",
                    evidence=evidence,
                    severity=severity,
                )
            )

        return results

    def _resolve_allowlist(self, policy: Policy) -> list[str]:
        configured = getattr(policy, "allowlist", {})
        if not isinstance(configured, dict):
            return self.ALLOWLIST.copy()

        rule_values = configured.get(self.rule_id, [])
        if not isinstance(rule_values, list):
            return self.ALLOWLIST.copy()

        merged = self.ALLOWLIST.copy()
        merged.extend(value for value in rule_values if isinstance(value, str))
        return merged

    def _iter_added_lines(self, diff_file: DiffFile) -> list[tuple[int, str]]:
        patch_lines = (diff_file.patch or "").splitlines()
        added_lines: list[tuple[int, str]] = []
        current_new_line = 0

        for raw_line in patch_lines:
            if raw_line.startswith("@@"):
                match = re.match(r"@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@", raw_line)
                if match:
                    current_new_line = int(match.group(1))
                continue

            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                added_lines.append((current_new_line, raw_line[1:]))
                current_new_line += 1
                continue

            if raw_line.startswith(" "):
                current_new_line += 1

        return added_lines

    def _calculate_entropy(self, string: str) -> float:
        if not string:
            return 0.0

        probability_by_char: dict[str, float] = {}
        total_chars = len(string)
        for char in string:
            probability_by_char[char] = probability_by_char.get(char, 0.0) + 1.0

        entropy = 0.0
        for count in probability_by_char.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        return entropy

    def _is_allowlisted(self, content: str, allowlist: list[str]) -> bool:
        return any(allowed_value and allowed_value in content for allowed_value in allowlist)

    def _matches_known_pattern(self, candidate: str) -> bool:
        for pattern, _ in self.PATTERNS.values():
            if pattern.fullmatch(candidate):
                return True
        return False

    def _is_placeholder(self, value: str) -> bool:
        lowered = value.strip("'\"`)._- ").lower()
        if lowered in self.PLACEHOLDER_KEYWORDS:
            return True
        if lowered.startswith("your_") or lowered.startswith("your-"):
            return True
        return len(set(lowered)) <= 2


RuleRegistry().register(SecretsScanRule)
