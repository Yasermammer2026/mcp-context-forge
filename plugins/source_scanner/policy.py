# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/policy.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Policy checker - evaluates findings against thresholds.
"""

# Future
from __future__ import annotations

# Standard
from typing import List, Optional

# Third-Party
from pydantic import BaseModel

# Local
from .types import Finding


class PolicyDecision(BaseModel):
    """Policy evaluation decision.

    Attributes:
        blocked: Whether to block the operation.
        reason: Explanation if blocked.
    """

    blocked: bool
    reason: Optional[str] = None


class PolicyChecker:
    """Evaluates findings against policy thresholds."""

    # Severity ordering: ERROR > WARNING > INFO
    _SEVERITY_ORDER = {"ERROR": 3, "WARNING": 2, "INFO": 1}

    def evaluate(
        self,
        findings: List[Finding],
        threshold: str,
        fail_on_critical: bool,
    ) -> PolicyDecision:
        """Evaluate findings against policy.

        Args:
            findings: All findings to evaluate.
            threshold: Minimum severity to consider (ERROR|WARNING|INFO).
            fail_on_critical: Whether to block on threshold violations.

        Returns:
            Policy decision with blocking status and reason.
        """
        # TODO: Filter findings where severity >= threshold
        # TODO: If fail_on_critical=False (audit mode): return PolicyDecision(blocked=False)
        # TODO: If fail_on_critical=True (enforce mode):
        #           Count findings by severity
        #           If any findings >= threshold:
        #               Generate reason like "Found 3 ERROR, 5 WARNING findings"
        #               return PolicyDecision(blocked=True, reason=...)
        #           Else:
        #               return PolicyDecision(blocked=False)
        raise NotImplementedError("PolicyChecker.evaluate not implemented")