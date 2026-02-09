#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/errors.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Xinyi

Shared exception types for Source Scanner Plugin.
"""

# Future
from __future__ import annotations


class SourceScannerError(Exception):
    """Base exception for source scanner plugin."""

    pass


class RepoFetchError(SourceScannerError):
    """Repository fetch/clone operation failed."""

    pass


class CloneTimeoutError(RepoFetchError):
    """Git clone operation timed out."""

    pass


class RepoSizeLimitError(RepoFetchError):
    """Repository exceeds size limit."""

    pass


class CheckoutError(RepoFetchError):
    """Git checkout operation failed."""

    pass


class ScannerError(SourceScannerError):
    """Scanner execution failed."""

    pass


class ScannerTimeoutError(ScannerError):
    """Scanner execution timed out."""

    pass


class ScannerNotFoundError(ScannerError):
    """Scanner executable not found."""

    pass


class ParseError(SourceScannerError):
    """Failed to parse scanner output."""

    pass


class PolicyError(SourceScannerError):
    """Policy evaluation failed."""

    pass
