#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bandit scanner runner for Source Scanner.

Location: ./plugins/source_scanner/scanners/bandit_scanner.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: "Fionn Gavin"

This module implements Bandit CLI integration for Python static security analysis.
Parses JSON output into normalized Finding objects.
"""

# Standard
import os
import logging
import json
from typing import Any, Literal

# First-Party
from plugins.source_scanner.utils.exec import run_command
from plugins.source_scanner.types import Finding

logger = logging.getLogger(__name__)


class BanditRunner:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.extra_args = config.get("extra_args", [])
        self.timeout = config.get("timeout", 300)

    async def run(self, repo_path: str, timeout_s: int) -> list[Finding]:
        # Build and run bandit command
        command = self.build_command(repo_path)
        result = await run_command(command, cwd=None, env=os.environ.copy(), timeout_seconds=timeout_s)

        # Bandit returns exit code 1 when issues are found — that's normal
        if result.returncode not in (0, 1):
            raise Exception(f"Bandit failed: {result.stderr}")

        data: dict[str, Any] = json.loads(result.stdout) if result.stdout else {}
        findings = self.parse_json_output(data)

        # Log message based on findings
        if not findings:
            logger.info("No findings detected.")
        else:
            logger.info(f"Found {len(findings)} issue(s):")
            for f in findings:
                logger.info(f"  [{f.severity}] {f.rule_id} at {f.file_path}:{f.line}")

        return findings

    def build_command(self, repo_path: str) -> list[str]:
        """Build bandit command with configured arguments."""
        return self._build_command(repo_path)

    def parse_json_output(self, bandit_data: dict[str, Any]) -> list[Finding]:
        """Parse Bandit JSON output into Finding objects."""
        return self._parse_json_output(bandit_data)

    def _build_command(self, repo_path: str) -> list[str]:
        command = ["bandit", "-r", repo_path, "-f", "json"]

        # Add any extra arguments from config
        command.extend(self.extra_args)

        return command

    def _parse_json_output(self, bandit_data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        # Handle empty or error case
        if not bandit_data or "errors" in bandit_data and not bandit_data.get("results"):
            return findings

        results = bandit_data.get("results", [])

        for result in results:
            finding = Finding(
                scanner="bandit",
                severity=_map_severity(result.get("issue_severity", "LOW")),
                rule_id=result.get("test_id", "unknown"),
                message=result.get("issue_text", ""),
                file_path=result.get("filename", None),
                line=result.get("line_number", None),
                column=result.get("col_offset", None),
                code_snippet=result.get("code", "").strip() or None,
                help_url=result.get("more_info", None),
            )
            findings.append(finding)

        return findings


Severity = Literal["ERROR", "WARNING", "INFO"]


def _map_severity(bandit_severity: str) -> Severity:
    """Map Bandit severity to normalized severity level."""
    severity_map: dict[str, Severity] = {
        "HIGH": "ERROR",
        "MEDIUM": "WARNING",
        "LOW": "INFO",
    }
    return severity_map.get(bandit_severity.upper(), "INFO")