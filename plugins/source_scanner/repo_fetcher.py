#!/usr/bin/env python3
# -- coding: utf-8 --
"""
Location: ./plugins/source_scanner/repo_fetcher.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Agnetha

"""

import os

from plugins.source_scanner.utils.exec import run_command


async def fetch_repo(repo_url: str, temp_folder: str, timeout_seconds: int = 300) -> None:
    """Clone repository to temporary folder.

    Args:
        repo_url: The URL of the repository to clone
        temp_folder: The temporary folder path where the repo will be cloned
        timeout_seconds: Timeout duration in seconds (default: 300)
    """
    git_command = ["git", "clone", "--depth", "1", "--", repo_url, temp_folder]
    await run_command(git_command, timeout_seconds=timeout_seconds, cwd=None, env=os.environ.copy())
