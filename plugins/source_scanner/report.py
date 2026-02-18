#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/report.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Author: Yanko

Generates a report from the scanner json findings
"""
# from plugins.source_scanner.parsing.normalizer import Normalizer

# Standard
from typing import List

# First-Party
from plugins.source_scanner.types import Finding


class Report:
    """Generates a report from the scanner's findings"""

    def __init__(self, findings: List[Finding]):
        """initialize the report

        Args:
            findings: List of findings from the scanner
        """

        self.findings = findings

    def summary(self) -> dict[str, int]:
        """gives a summary of the findings

        Returns:
            A dictionary with a summary of the findings"""

        levels = {"ERROR": 0, "WARNING": 0, "INFO": 0}

        for finding in self.findings:
            levels[finding["severity"]] += 1

        summary = {
            "total_findings": len(self.findings),
            "total_issues": (levels["ERROR"] + levels["WARNING"] + levels["INFO"]),
            "ERROR": levels["ERROR"],
            "WARNING": levels["WARNING"],
            "INFO": levels["INFO"],
        }
        return summary

    def ordered(self) -> dict[str, dict[str, int]]:
        """gives an rdered list of the findings

        Returns:
            A dictionary with 3 dictionaries named after the severity levels, each containing issues of that severity and their counts"""

        ordered: dict[str, dict[str, int]] = {"ERROR": {}, "WARNING": {}, "INFO": {}}

        for finding in self.findings:
            if finding["issue"] not in ordered[finding["severity"]]:
                ordered[finding["severity"]][finding["issue"]] = 1
            else:
                ordered[finding["severity"]][finding["issue"]] += 1
        return ordered
