# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/config.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Configuration models for Source Scanner Plugin.
"""

# Future
from __future__ import annotations

# Standard
from typing import List, Optional

# Third-Party
from pydantic import BaseModel, Field


class SemgrepConfig(BaseModel):
    """Semgrep scanner configuration.

    Attributes:
        enabled: Whether Semgrep is enabled.
        rulesets: List of ruleset identifiers (e.g., p/security-audit).
        extra_args: Additional CLI arguments.
    """

    enabled: bool = True
    rulesets: List[str] = Field(
        default_factory=lambda: [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/python",
            "p/javascript",
        ]
    )
    extra_args: List[str] = Field(default_factory=list)


class BanditConfig(BaseModel):
    """Bandit scanner configuration.

    Attributes:
        enabled: Whether Bandit is enabled.
        severity: Minimum severity level (low/medium/high).
        confidence: Minimum confidence level (low/medium/high).
    """

    enabled: bool = True
    severity: str = "medium"
    confidence: str = "medium"


class SourceScannerConfig(BaseModel):
    """Configuration for source scanner plugin.

    Attributes:
        semgrep: Semgrep configuration.
        bandit: Bandit configuration.
        severity_threshold: Minimum severity to block (ERROR|WARNING|INFO).
        fail_on_critical: Whether to block on threshold violations.
        clone_timeout_seconds: Timeout for git clone operations.
        scan_timeout_seconds: Timeout for scan operations.
        max_repo_size_mb: Maximum repository size in MB.
        github_token_env: Environment variable for GitHub token.
        cache_by_commit: Whether to cache results by commit SHA.
        cache_ttl_hours: Cache time-to-live in hours.
    """

    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    bandit: BanditConfig = Field(default_factory=BanditConfig)
    severity_threshold: str = "WARNING"  # ERROR | WARNING | INFO
    fail_on_critical: bool = True
    clone_timeout_seconds: int = 120
    scan_timeout_seconds: int = 600
    max_repo_size_mb: Optional[int] = 500
    github_token_env: str = "GITHUB_TOKEN"
    cache_by_commit: bool = True
    cache_ttl_hours: int = 168  # 1 week