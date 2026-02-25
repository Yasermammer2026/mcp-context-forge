# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/mcp_tiers/catalog.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Yanko

Makes a catalog of MCP servers that go trough server_tier.
"""

# Standard
import uuid

# Third-Party
from server_tier import server_tier


class catalog:
    """A class that takes servers and aproved tiers of servers"""

    def __init__(self, servers: list[server_tier] = [], approved: list[bool] = [True, True, True, False]):
        """Initialize the catalog with servers and approved tiers"""
        self.servers = servers
        self.approved = {"verified": approved[0], "standard": approved[1], "community": approved[2], "untrusted": approved[3]}

    def display(self):
        """Displays the catalog of servers"""

        # can do, but will slow the program if done every time we want to display self.sort_servers()

        for server in self.servers:
            print(server.score)
            print(self.settings("minimum_trust_score"))
            if server.score < self.settings("minimum_trust_score"):  # type: ignore
                continue
            print(f"Name: {server.name}")
            print(f"Version: {server.version}")
            print(f"Source Type: {server.source_type}")
            if self.settings("show_trust_score"):
                print(f"Trust Score: {server.score}")
            if self.settings("show_vulnerability_summary"):
                print(f"Vulnerability Summary: {server.scanning()}")
            if self.settings("show_last_assessed"):
                print(f"Last Assessed: {server.last_checked}")
            if self.settings("show_sbom_indicator"):
                print(f"SBOM Indicator: {'Yes' if server.path else 'No'}")
            print("\n")

    def add_server(self, server: server_tier):
        """Adds a server to the catalog"""
        self.servers.append(server)

    def remove_server(self, server_id: uuid.UUID):
        """Removes a server from the catalog by its ID"""
        self.servers = [s for s in self.servers if s.id != server_id]  # Implement a better way to remove?

    def settings(self, setting: str):
        """Returns the display settings for the catalog"""
        settings = {"show_trust_score": True, "show_vulnerability_summary": True, "show_last_assessed": True, "show_sbom_indicator": True, "default_sort": "trust_score", "minimum_trust_score": 0}

        return settings[setting]  # type: ignore

    def sort_servers(self, by: str = "trust_score"):
        """Sorts the servers in the catalog (Very good, but maybe make a red-black tree as faster due to no sorting needed)"""
        if by == "trust_score":
            self.servers.sort(key=lambda s: s.score, reverse=True)
        elif by == "last_assessed":
            self.servers.sort(key=lambda s: s.last_checked, reverse=True)
        elif by == "vulnerability_count":
            self.servers.sort(key=lambda s: sum(s.scanning()), reverse=True)
        # Add more sorting options if needed
