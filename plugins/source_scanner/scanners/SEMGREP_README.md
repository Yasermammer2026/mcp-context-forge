# SemgrepRunner - Quick Implementation Guide

## Class & File Structure

**File Location:**
```
plugins/source_scanner/scanners/semgrep_runner.py
```

**Main Class:**
```python
class SemgrepRunner:
    """Scanner runner for Semgrep with SARIF output parsing."""
```

**Data Class (Simple Result Model):**
```python
from dataclasses import dataclass

@dataclass
class ScanResult:
    scanner_name: str  # "semgrep"
    findings: list  # Raw SARIF result dicts
```

## Required Methods

| Method | Purpose | Input | Output |
|--------|---------|-------|--------|
| `__init__(config)` | Initialize with validation | `Dict[str, Any]` config | None (store attributes) |
| `run(repo_path)` | Execute scan | `Union[Path, str]` | `ScanResult` |
| `_build_command(project_path)` | Build CLI args | `str` path | `List[str]` command |
| `_parse_sarif_output(json_output)` | Parse JSON → findings | `Dict[str, Any]` JSON | `List[dict]` findings |
| `_get_rule_name(rule_id)` | Map rule ID to name | `str` rule_id | `str` readable name |

## Constructor Validation Checklist

✅ Store: `self.enabled`, `self.rulesets`, `self.extra_args`, `self.timeout`
✅ Validate: `rulesets` is non-empty list
✅ Check: `shutil.which("semgrep")` exists
✅ Raise: `ScannerNotFoundError` if semgrep not found
✅ Raise: `ValueError` if config invalid

## Test Execution

**Run all tests:**
```bash
pytest tests/unit/plugins/test_source_scanner/test_semgrep_runner.py -v
```

**Run specific category:**
```bash
pytest tests/unit/plugins/test_source_scanner/test_semgrep_runner.py::TestSemgrepRunner::test_init_with_default_config -v
```

**Run with coverage:**
```bash
pytest tests/unit/plugins/test_source_scanner/test_semgrep_runner.py --cov=plugins.source_scanner.scanners.semgrep_runner --cov-report=term-missing
```

## Expected Test Results

### All 29 tests should PASS:

**Initialization Tests (5)** ✅
```
test_init_with_default_config
test_init_with_custom_rulesets
test_init_with_extra_args
test_init_validates_rulesets_not_empty
test_semgrep_not_installed
```

**Execution Tests (6)** ✅
```
test_scan_python_project
test_scan_javascript_project
test_scan_with_specific_rulesets
test_scan_timeout_exceeded
test_scan_no_findings
test_scan_with_multiple_languages
```

**SARIF Parsing Tests (8)** ✅
```
test_parse_sarif_basic
test_parse_sarif_extract_rule_id
test_parse_sarif_extract_severity_level
test_parse_sarif_extract_message
test_parse_sarif_extract_file_location
test_parse_sarif_extract_code_snippet
test_parse_sarif_empty_findings
test_parse_sarif_multiple_runs
test_parse_sarif_missing_optional_fields
```

**Command Building Tests (5)** ✅
```
test_build_semgrep_command_basic
test_build_semgrep_command_json_output
test_build_semgrep_command_with_rulesets
test_build_semgrep_command_with_extra_args
test_build_semgrep_command_single_ruleset
```

**Integration Tests (5)** ✅
```
test_scan_and_parse_integration
test_scan_with_mock_subprocess
test_scan_handles_rule_id_variations
test_scan_with_multiple_languages
test_semgrep_rule_id_to_name_mapping
```

## Command Building Format

Your `_build_command()` should return:
```python
[
    "semgrep",
    "--json",
    "-c", "p/security-audit",
    "-c", "p/python",
    "--verbose",  # any extra_args
    "/path/to/project"  # project_path last
]
```

## SARIF Parsing Format

Your `_parse_sarif_output()` should return **raw** SARIF results:
```python
[
    {
        "ruleId": "python.django.security.sql-injection",
        "level": "error",
        "message": {"text": "SQL injection..."},
        "locations": [...]
    },
    {
        "ruleId": "python.security.hardcoded-sql-string",
        "level": "warning",
        "message": {"text": "Hardcoded SQL..."},
        "locations": [...]
    }
]
```

**NOT normalized Finding objects** - return raw SARIF dicts.

## Return Type from run()

```python
result = runner.run("/path/to/repo")

# result.scanner_name == "semgrep"
# result.findings == [raw SARIF dicts from _parse_sarif_output()]
```

## Exception Types to Use

```python
from plugins.source_scanner.errors import (
    ScannerNotFoundError,    # semgrep executable not found
    ScannerTimeoutError,     # scan exceeded timeout
    ParseError,              # JSON parsing failed
)
```

## Code Quality Requirements

- ✅ All methods have type hints: `def run(self, repo_path: Union[Path, str]) -> ScanResult:`
- ✅ All methods have docstrings (Google style)
- ✅ Add logging: `logger.info(f"Running Semgrep scan: {repo_path}")`
- ✅ No Pylance errors: type annotations for all variables
- ✅ Code formatted: `make black isort`
- ✅ Linting passes: `make flake8 pylint mypy`

## Imports Template

```python
# Standard
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
import logging
import shutil
import subprocess

# First-Party
from mcpgateway.plugins.source_scanner.errors import (
    ScannerNotFoundError,
    ScannerTimeoutError,
    ParseError,
)

# Local
from .errors import ScannerNotFoundError, ScannerTimeoutError, ParseError
```

## Success Criteria

Before submitting PR:
- [ ] All 29 tests pass: `pytest tests/unit/plugins/test_source_scanner/test_semgrep_runner.py -v`
- [ ] Coverage ≥ 80%
- [ ] No lint errors: `make flake8 pylint mypy`
- [ ] Class name is `SemgrepRunner`
- [ ] File is `plugins/source_scanner/scanners/semgrep_runner.py`
- [ ] Return type from `run()` is `ScanResult` with `scanner_name` and `findings`
- [ ] `_parse_sarif_output()` returns **raw SARIF dicts**, not normalized

## Key Notes

🔑 **DO:** Return raw SARIF results from `_parse_sarif_output()`
🔑 **DON'T:** Normalize to Finding objects (that's done later by the plugin)
🔑 **DO:** Aggregate results from ALL runs in SARIF output
🔑 **DON'T:** Only process first run
🔑 **DO:** Validate rulesets is not empty in constructor
🔑 **DON'T:** Skip checking if semgrep is installed
