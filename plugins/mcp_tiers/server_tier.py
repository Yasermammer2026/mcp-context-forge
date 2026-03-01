# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Location: ./plugins/mcp_tiers/server_tier.py.
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Yanko

takes an MCP server and assigns it a trust tier based on scan of the code and time since last update
"""

# Standard
import datetime
from typing import Any
import uuid


class server_tier:
    """A class that represents a server and assings trust scores to it."""

    def __init__(self, name: str, version: str = "", source_type: str = "", checked: datetime.datetime = None, path: str = "", errors: dict[str, int]): # type: ignore
        """Initialize class with the wanted inputs."""
        self.id = uuid.uuid4()
        self.name = name
        self.version = version
        self.source_type = source_type
        self.last_checked = checked
        self.last_updated = datetime.datetime.now()
        self.errors = {"critical": errors.get("critical", -1), "high": errors.get("high", -1), "medium": errors.get("medium", -1)}
        self.score = self.trust_score()
        self.trust_tier = self.assign_tier()
        self.path = path
        self.sbom = False  # will be updated based on actual SBOM

    def trust_tiers(self, tier: str) -> dict[str, Any]:
        """function that returns the tier needed."""
        tiers = {
            "verified": {"min_score": 90, "badge_color": "#22c55e", "badge_icon": "shield-check", "requires_manual_review": True, "verification_expiry_days": 90},  # green
            "standard": {"min_score": 70, "badge_color": "#3b82f6", "badge_icon": "shield"},  # blue
            "community": {"min_score": 50, "badge_color": "#eab308", "badge_icon": "shield-question"},  # yellow
            "untrusted": {
                "min_score": float("-inf"),
                "badge_color": "#ef4444",
                "badge_icon": "shield-x",
                "requires_approval": True,
                "warning_message": "This server has not been security verified",
            },  # red
        }
        return tiers[tier]

    def trust_score(self) -> float:
        """calculates trust score and returns it."""
        if self.errors["critical"] == -1 or self.errors["high"] == -1 or self.errors["medium"] == -1:
            return -1
        else:
            return 100 - (self.errors["critical"] * 30) - (self.errors["high"] * 10) - (self.errors["medium"] * 3) - ((datetime.datetime.now() - self.last_updated).days * 0.5)

    def assign_tier(self) -> str:
        """assigns a tier based on score and other requirements"""
        if self.score >= self.trust_tiers("verified")["min_score"] and self.last_checked is not None and (datetime.datetime.now() - self.last_checked).days <= 90 and self.last_checked is not None:  # type: ignore
            return "verified"
        elif self.score >= self.trust_tiers("standard")["min_score"]:
            return "standard"
        elif self.score >= self.trust_tiers("community")["min_score"]:
            return "community"
        else:
            return "untrusted"
