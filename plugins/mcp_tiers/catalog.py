# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/mcp_tiers/catalog.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Yanko

Makes a catalog of MCP servers that go trough server_tier.
"""

# Standard
from datetime import datetime
import uuid

# Third-Party
from server_tier import server_tier
import json
import csv
from fpdf import FPDF


class catalog:
    """A class that takes servers and aproved tiers of servers"""

    def __init__(self, servers: list[server_tier] = [], approved: list[bool] = [True, True, True, False]):
        """Initialize the catalog with servers and approved tiers"""
        self.servers = servers
        self.approved = {"verified": approved[0], "standard": approved[1], "community": approved[2], "untrusted": approved[3]}

    def display(self) -> dict[uuid.UUID, dict[str, str | int | list[int]]]: 
        """Displays the catalog of servers by returning a dict of all servers which are dicts themselves"""

        # can do, but will slow the program if done every time we want to display self.sort_servers()

        output = {}
        for server in self.servers:
            if server.score < self.settings("minimum_trust_score"):  # type: ignore
                continue
            
            server_data: dict[str, str | int | list[int]] = {
                "name": server.name,
                "version": server.version,
                "source_type": server.source_type,
            }
            
            if self.settings("show_trust_score"):
                server_data.update({"trust_score" : server.score})
            if self.settings("show_vulnerability_summary"):
                server_data.update({"vulnerability_summary": server.errors})
            if self.settings("show_last_assessed"):
                server_data.update({"last_assessed": (server.last_checked - datetime.now()).days})
            if self.settings("show_sbom_indicator"):
                server_data.update({"sbom" : server.sbom})
            
            output[server.id] = server_data
        
        return output # type: ignore

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

    def sort_servers(self, sorting: str = "trust_score"):
        """Sorts the servers in the catalog (Very good, but maybe make a red-black tree as faster due to no sorting needed)"""
        if sorting == "trust_score":
            self.servers.sort(key=lambda s: s.score, reverse=True)
        elif sorting == "last_assessed":
            self.servers.sort(key=lambda s: s.last_checked, reverse=True)
        elif sorting == "vulnerability_count":
            self.servers.sort(key=lambda s: sum(s.errors), reverse=True)
        # Add more sorting options if needed

    def export(self, format: str = "json", filename: str = "catalog", path: str = "./"):
        """Exports the catalog to a file or database (Not implemented yet)"""
        data = self.display()  # Get the data to export
        
        if format == "json":
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        elif format == "csv":
            with open(filename, 'w', newline='') as f:
                if not data:
                    return
                fieldnames = list(data[next(iter(data))].keys()) if data else []
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for server_data in data.values():
                    writer.writerow(server_data)
        elif format == "pdf":
            pdf_doc = FPDF()
            pdf_doc.add_page()
            pdf_doc.set_font("Arial", size=12)
            for _, server_data in data.items():
                pdf_doc.cell(0, 10, f"Server: {server_data.get('name', 'Unknown')}", ln=True)
                for key, value in server_data.items():
                    pdf_doc.cell(0, 10, f"  {key}: {value}", ln=True)
                pdf_doc.cell(0, 10, "", ln=True)
            pdf_doc.output(f"{path}{filename}.pdf")
        else:
            raise ValueError(f"Unsupported export format: {format}")