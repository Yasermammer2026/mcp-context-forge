# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Location: ./plugins/mcp_tiers/testing.py.
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Yanko

takes an MCP server and assigns it a trust tier based on scan of the code and time since last update
"""

import catalog
import server_tier

test_catalog = catalog.catalog()

test_server1 = server_tier.server_tier(name = "test1", errors={"critical" : 1, "high" : 1, "medium" : 1})
test_server2 = server_tier.server_tier(name = "test2", errors={"critical" : 0, "high" : 0, "medium" : 0})

test_catalog.add_server(test_server1)
test_catalog.add_server(test_server2)

if test_server1.trust_tier == "community":
    print("Test passed: server assigned to correct tier")
else:
    print("Test failed: server assigned to wrong tier")

if test_server1.score == 57:
    print("correct score calculated")
else:
    print("incorrect score calculated")

if test_catalog.servers[0].id == test_server1.id:
    print("server added to catalog with correct id")
else:
    print("server id in catalog doesnt match server id")

if test_server1.trust_tiers("verified") == {"min_score": 90, "badge_color": "#22c55e", "badge_icon": "shield-check", "requires_manual_review": True, "verification_expiry_days": 90}:
    print("correct tier information returned")
else:
    print("problem with verified tier info")

if test_server1.trust_tiers("standard") == {"min_score": 70, "badge_color": "#3b82f6", "badge_icon": "shield"}:
    print("correct tier information returned")
else:
    print("problem with standart tier info")

if test_server1.trust_tiers("community") == {"min_score": 50, "badge_color": "#eab308", "badge_icon": "shield-question"}:
    print("correct tier information returned")
else:
    print("problem with community tier info")

if test_server1.trust_tiers("untrusted") == {"min_score": float("-inf"),"badge_color": "#ef4444", "badge_icon": "shield-x","requires_approval": True,"warning_message": "This server has not been security verified"}:
    print("correct tier information returned")
else:
    print("problem with untrusted tier info")

test_catalog.sort_servers()
if test_catalog.servers[0].id == test_server1.id:
    print("servers sorted incorrectly")
else:
    print("server sorted correctly")

for server in test_catalog.servers:
    print("Server Name:", server.name)
    print("Trust Score:", server.score)