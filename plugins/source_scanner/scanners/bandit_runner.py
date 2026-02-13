#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bandit Security Scanner Integration Module
Location: ./plugins/source_scanner/scanners/bandit_scanner.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Author: Fionn Gavin

Purpose: Integrates Bandit static security scanner for Python projects.
         Provides standardized output for report generation and database storage.

Usage:
    As a standalone script:
        python bandit_scanner.py /path/to/project

    As an imported module:
        from bandit_scanner import scan_project
        results = scan_project('/path/to/project')

Output:
    - JSON file with scan results (bandit_results.json)
    - Standardized dictionary format for team integration
    - Optional terminal output for debugging

"""

# Standard
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys

# ============================================================================
# INSTALLATION & VALIDATION FUNCTIONS
# ============================================================================


def check_bandit_installed():
    """
    Check if Bandit is installed on the system.

    Returns:
        bool: True if Bandit is installed, False otherwise

        Prints installation instructions if Bandit is not found
    """
    try:
        subprocess.run(["bandit", "--version"], capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("=" * 70)
        print("ERROR: Bandit is not installed!")
        print("=" * 70)
        print("\nBandit is required to scan Python projects for security issues.")
        print("\nTo install Bandit, run:")
        print("  pip install bandit")
        print("\nFor more information: https://bandit.readthedocs.io/")
        print("=" * 70)
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: Bandit check timed out")
        return False


def has_python_files(project_path):
    """
    Check if the project directory contains Python files.

    Args:
        project_path (str): Path to the project directory

    Returns:
        bool: True if Python files are found, False otherwise

    Side Effects:
        Prints warning messages if no Python files found
    """
    path = Path(project_path)

    if not path.exists():
        print(f"ERROR: Path '{project_path}' does not exist!")
        return False

    if not path.is_dir():
        print(f"ERROR: Path '{project_path}' is not a directory!")
        return False

    python_files = list(path.rglob("*.py"))

    if not python_files:
        print(f"WARNING: No Python files found in '{project_path}'")
        print("Bandit only works with Python projects.")
        print("If this is a multi-language project, other scanners may be needed.")
        return False

    print(f"✓ Found {len(python_files)} Python file(s) to scan")
    return True


# ============================================================================
# CORE SCANNING FUNCTIONS
# ============================================================================


def run_bandit(project_path, output_file=None, verbose=True):
    """
    Execute Bandit security scanner on the specified project.

    Args:
        project_path (str): Path to the project directory to scan
        output_file (str, optional): Path to save JSON results
        verbose (bool): Whether to print progress messages to terminal

    Returns:
        dict: Raw Bandit results in JSON format, or None if scan fails

    Example:
        >>> results = run_bandit('/path/to/project', verbose=True)
        >>> print(f"Found {len(results['results'])} issues")
    """
    try:
        cmd = ["bandit", "-r", project_path, "-f", "json"]

        if verbose:
            print("\n" + "=" * 70)
            print("STARTING BANDIT SCAN")
            print("=" * 70)
            print(f"Target: {project_path}")
            print(f"Command: {' '.join(cmd)}")
            print("=" * 70 + "\n")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.stdout:
            bandit_results = json.loads(result.stdout)
        else:
            if verbose:
                print("WARNING: Bandit produced no output")
            return None

        if output_file:
            save_path = Path(output_file)
            save_path.parent.mkdir(parents=True, exist_ok=True)

            with open(save_path, "w") as f:
                json.dump(bandit_results, f, indent=2)

            if verbose:
                print(f"✓ Raw results saved to: {output_file}\n")

        return bandit_results

    except subprocess.TimeoutExpired:
        print("ERROR: Bandit scan timed out (>5 minutes)")
        print("The project may be too large. Consider scanning subdirectories.")
        return None

    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse Bandit JSON output: {e}")
        print("Bandit may have produced invalid output.")
        return None

    except Exception as e:
        print(f"ERROR: Failed to run Bandit: {type(e).__name__}: {e}")
        return None


# ============================================================================
# STANDARDIZATION FOR INTEGRATION
# ============================================================================


def standardize_results(bandit_results):
    """
    Convert Bandit's raw output to standardized format

    Args:
        bandit_results (dict): Raw results from Bandit in JSON format

    Returns:
        dict: Standardized results with the following structure:
            {
                'scanner': str,
                'scanner_version': str,
                'timestamp': str,
                'scan_timestamp': str,
                'files_scanned': int,
                'total_issues': int,
                'severity_breakdown': {
                    'HIGH': int,
                    'MEDIUM': int,
                    'LOW': int
                },
                'findings': [
                    {
                        'id': str,
                        'title': str,
                        'severity': str,
                        'confidence': str,
                        'file': str,
                        'line': int,
                        'code_snippet': str,
                        'description': str,
                        'cwe': dict,
                        'more_info': str
                    }
                ]
            }

    Example:
        >>> standardized = standardize_results(raw_results)
        >>> for finding in standardized['findings']:
        ...     if finding['severity'] == 'HIGH':
        ...         print(f"Critical issue: {finding['title']}")
    """
    if not bandit_results:
        return None

    standardized = {
        "scanner": "bandit",
        "scanner_version": bandit_results.get("version", "unknown"),
        "timestamp": datetime.now().isoformat(),
        "scan_timestamp": bandit_results.get("generated_at", ""),
        "files_scanned": len(bandit_results.get("metrics", {})),
        "total_issues": len(bandit_results.get("results", [])),
        "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
    }

    for issue in bandit_results.get("results", []):
        severity = issue.get("issue_severity", "UNKNOWN")
        if severity in standardized["severity_breakdown"]:
            standardized["severity_breakdown"][severity] += 1

        finding = {
            "id": issue.get("test_id", "UNKNOWN"),
            "title": issue.get("issue_text", "No description"),
            "severity": severity,
            "confidence": issue.get("issue_confidence", "UNKNOWN"),
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "code_snippet": issue.get("code", "").strip(),
            "description": issue.get("issue_text", ""),
            "cwe": issue.get("issue_cwe", {}),
            "more_info": issue.get("more_info", ""),
        }

        standardized["findings"].append(finding)

    return standardized


# ============================================================================
# DISPLAY & REPORTING FUNCTIONS
# ============================================================================


def display_results(results, verbose=True):
    """
    Display scan results in a human readable format to the terminal.

    Primarily for debugging and standalone usage.
    Production reports should use the report generation component.

    Args:
        results (dict): Standardized results from standardize_results()
        verbose (bool): If True, show detailed issue information

    Side Effects:
        Prints formatted output to stdout
    """
    if not results:
        print("No results to display")
        return

    print("\n" + "=" * 70)
    print("BANDIT SECURITY SCAN RESULTS")
    print("=" * 70)

    print(f"\nScanner: {results['scanner']} v{results['scanner_version']}")
    print(f"Scan completed: {results['timestamp']}")
    print(f"Files scanned: {results['files_scanned']}")
    print(f"Total issues found: {results['total_issues']}")

    print("\nSeverity Breakdown:")
    print(f"  HIGH:   {results['severity_breakdown']['HIGH']}")
    print(f"  MEDIUM: {results['severity_breakdown']['MEDIUM']}")
    print(f"  LOW:    {results['severity_breakdown']['LOW']}")

    if results["findings"]:
        print("\n" + "-" * 70)
        print("DETAILED FINDINGS:")
        print("-" * 70)

        for i, finding in enumerate(results["findings"], 1):
            print(f"\n[{i}] {finding['id']}: {finding['title']}")
            print(f"    Severity:   {finding['severity']}")
            print(f"    Confidence: {finding['confidence']}")
            print(f"    Location:   {finding['file']}:{finding['line']}")

            if verbose and finding["code_snippet"]:
                print(f"    Code:       {finding['code_snippet'][:100]}...")
    else:
        print("\n✓ No security issues found!")

    print("\n" + "=" * 70)


def save_standardized_results(results, output_file="bandit_standardized.json"):
    """
    Save standardized results to a JSON file.

    Args:
        results (dict): Standardized results dictionary
        output_file (str): Path to save the standardized JSON

    Returns:
        bool: True if save successful, False otherwise
    """
    try:
        save_path = Path(output_file)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            json.dump(results, f, indent=2)

        print(f"✓ Standardized results saved to: {output_file}")
        return True

    except Exception as e:
        print(f"ERROR: Failed to save standardized results: {e}")
        return False


# ============================================================================
# PUBLIC API FOR TEAM INTEGRATION
# ============================================================================


def scan_project(project_path, save_results=True, verbose=True):
    """
    Main entry point for scanning a project with Bandit.

    Args:
        project_path (str): Path to the project directory to scan
        save_results (bool): Whether to save results to JSON files
        verbose (bool): Whether to print progress and results to terminal

    Returns:
        dict: Standardized results dictionary, or None if scan fails

    """
    if not check_bandit_installed():
        return None

    if not has_python_files(project_path):
        return None

    raw_results = run_bandit(project_path, output_file="bandit_raw.json" if save_results else None, verbose=verbose)

    if not raw_results:
        return None

    standardized = standardize_results(raw_results)

    if save_results and standardized:
        save_standardized_results(standardized, "bandit_standardized.json")

    if verbose:
        display_results(standardized)

    return standardized


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================


def main():
    """
    Command-line interface for standalone usage.

    Usage:
        python bandit_scanner.py [project_path]

    If no path is provided, scans the current directory.
    """
    print("\n" + "=" * 70)
    print("BANDIT SECURITY SCANNER")
    print("Python Static Security Analysis Tool")
    print("=" * 70)

    if len(sys.argv) < 2:
        project_path = os.getcwd()
        print(f"No path provided. Scanning current directory: {project_path}")
    else:
        project_path = sys.argv[1]
        print(f"Scanning provided path: {project_path}")

    print("=" * 70)

    results = scan_project(project_path, save_results=True, verbose=True)

    if results is None:
        print("\n Scan failed or incomplete")
        sys.exit(1)
    elif results["total_issues"] > 0:
        print(f"\n Scan complete: {results['total_issues']} issue(s) found")
        sys.exit(0)
    else:
        print("\n Scan complete: No issues found")
        sys.exit(0)


# ============================================================================
# MODULE ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
