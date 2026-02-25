# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/mcp_tiers/server_tier.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Yanko

takes an MCP server and assigns it a trust tier based on scan of the code and time since last update
"""

# Standard
import datetime
import uuid


class server_tier:
    """A class that represents a server and assings trust scores to it"""

    def __init__(self, name: str = "", version: str = "", source_type: str = "", checked: datetime.datetime = None, path: str = ""):  # type: ignore
        """Initialize class with the wanted inputs"""
        self.id = uuid.uuid4()
        self.name = name
        self.version = version
        self.source_type = source_type
        self.last_checked = checked
        self.last_updated = datetime.datetime.now()
        self.score = self.trust_score()
        self.trust_tier = self.assign_tier()
        self.path = path

    def trust_tiers(self, tier: str) -> dict[str, any]:  # type: ignore
        """function that returns the tier needed"""
        tiers = {
            "verified": {"min_score": 90, "badge_color": "#22c55e", "badge_icon": "shield-check", "requires_manual_review": True, "verification_expiry_days": 90},  # green
            "standard": {"min_score": 70, "badge_color": "#3b82f6", "badge_icon": "shield"},  # blue
            "community": {"min_score": 50, "badge_color": "#eab308", "badge_icon": "shield-question"},  # yellow
            "untrusted": {
                "min_score": float("-inf"),
                "badge_color": "#ef4444",  # red
                "badge_icon": "shield-x",
                "requires_approval": True,
                "warning_message": "This server has not been security verified",
            },
        }
        return tiers[tier]  # type: ignore

    # Catalog display settings

    # a function that calculates a trust score
    # input:
    #
    def trust_score(self, errors: list[int] = [-1, -1, -1]) -> int:
        """calculates trust score and returns it"""
        if errors[0] == errors[1] == errors[2] == -1:
            print("bad")
            return -1
        else:
            return 100 - (errors[0] * 50) - (errors[1] * 20) - (errors[2] * 5) - ((datetime.datetime.now() - self.last_updated).days * 1)

    # Scanning and returning the errors in a list of critical
    def scanning(self) -> list[int]:
        """calls the scanner and returns the problems"""
        if self.path == "":
            return [-1, -1, -1]
        else:
            #   #TODO add scanner that returns the 3 error types
            return [0, 0, 0]

    def assign_tier(self):
        """assigns a tier based on score and other requirements"""
        if self.score >= self.trust_tiers("verified")["min_score"] and (datetime.datetime.now() - self.last_checked).days <= 90 and self.last_checked is not None:  # type: ignore
            return "verified"
        elif self.score >= self.trust_tiers("standard")["min_score"]:  # type: ignore
            return "standard"
        elif self.score >= self.trust_tiers("community")["min_score"]:  # type: ignore
            return "community"
        else:
            return "untrusted"
