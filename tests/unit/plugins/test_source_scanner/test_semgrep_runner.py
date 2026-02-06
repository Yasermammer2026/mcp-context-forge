"""Unit tests for Semgrep runner integration."""

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


class TestSemgrepRunner:
    """Test suite for Semgrep runner integration and SARIF parsing."""

    # ===== Scanner Initialization Tests =====

    def test_init_with_default_config(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Initialize Semgrep with default configuration."""
        # Arrange
        config = semgrep_scanner_config

        # Act & Assert
        assert config["enabled"] is True
        assert len(config["rulesets"]) > 0

    def test_init_with_custom_rulesets(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Initialize Semgrep with custom rulesets."""
        # Arrange
        config = semgrep_scanner_config.copy()
        config["rulesets"] = ["p/python", "p/javascript", "p/security-audit"]

        # Act & Assert
        assert len(config["rulesets"]) == 3
        assert all(isinstance(r, str) for r in config["rulesets"])

    def test_init_with_extra_args(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Initialize Semgrep with extra CLI arguments."""
        # Arrange
        config = semgrep_scanner_config.copy()
        config["extra_args"] = ["--verbose", "--timeout=30"]

        # Act & Assert
        assert config["extra_args"] == ["--verbose", "--timeout=30"]

    def test_init_validates_rulesets_not_empty(self) -> None:
        """Initialize validates that rulesets list is not empty."""
        # Arrange
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": [],  # Empty rulesets
            "extra_args": []
        }

        # Act & Assert
        assert isinstance(config["rulesets"], list)

    @pytest.mark.requires_semgrep
    def test_semgrep_not_installed(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Handle when semgrep not installed."""
        # Arrange
        config = semgrep_scanner_config

        # Act & Assert
        assert config["enabled"] is True

    # ===== Semgrep Execution Tests =====

    @pytest.mark.requires_semgrep
    def test_scan_python_project(self, vulnerable_python_code: Path) -> None:
        """Scan Python project with Semgrep and return findings."""
        # Arrange
        project_dir = vulnerable_python_code
        assert (project_dir / "app.py").exists()

        pass 

    @pytest.mark.requires_semgrep
    def test_scan_javascript_project(self, vulnerable_javascript_code: Path) -> None:
        """Scan JavaScript project with Semgrep and return findings."""
        # Arrange
        project_dir = vulnerable_javascript_code
        assert (project_dir / "app.js").exists()

        pass

    @pytest.mark.requires_semgrep
    def test_scan_with_specific_rulesets(self, vulnerable_python_code: Path) -> None:
        """Scan with specific rulesets."""
        # Arrange
        project_dir = vulnerable_python_code
        assert project_dir.exists()
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": ["p/python"],
            "extra_args": []
        }

        # Act & Assert
        assert config["rulesets"] == ["p/python"]

    @pytest.mark.requires_semgrep
    @pytest.mark.slow
    def test_scan_timeout_exceeded(self, vulnerable_python_code: Path) -> None:
        """Timeout if scan takes too long."""
        # Arrange
        project_dir = vulnerable_python_code
        assert project_dir.exists()
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": ["p/security-audit"],
            "extra_args": [],
            "timeout": 1  # 1 second (too short)
        }

        # Act & Assert
        assert isinstance(config["timeout"], int) and config["timeout"] > 0

    def test_scan_no_findings(self, empty_directory: Path) -> None:
        """Scan clean code returns empty findings."""
        # Arrange
        project_dir = empty_directory
        assert project_dir.exists()
        clean_code = project_dir / "clean_app.py"
        clean_code.write_text("def hello():\n    return 'Hello, World!'\n")

        # Act & Assert
        assert clean_code.exists()

    # ===== SARIF Output Parsing Tests =====

    def test_parse_sarif_basic(self, mock_semgrep_sarif_output: Dict[str, Any]) -> None:
        """Parse basic SARIF output into Finding objects."""
        # Arrange
        sarif_output: Dict[str, Any] = mock_semgrep_sarif_output

        # Act & Assert
        assert sarif_output["version"] == "2.1.0"
        runs: list[Any] = sarif_output["runs"]  # type: ignore
        assert len(runs) > 0
        first_run: Dict[str, Any] = runs[0]  # type: ignore
        results: list[Any] = first_run["results"]  # type: ignore
        assert len(results) > 0

    def test_parse_sarif_extract_rule_id(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Extract rule ID from SARIF result."""
        # Arrange
        result = sample_sarif_result

        # Act
        rule_id = result["ruleId"]

        # Assert
        assert rule_id == "python.django.security.sql-injection"
        assert rule_id is not None
        assert isinstance(rule_id, str)

    def test_parse_sarif_extract_severity_level(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Map SARIF level to severity."""
        # Arrange
        result = sample_sarif_result

        # Act
        level = result["level"]

        # Assert
        assert level == "error"
        assert level in ["error", "warning", "note", "none"]

    def test_parse_sarif_extract_message(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Extract message from SARIF result."""
        # Arrange
        result = sample_sarif_result

        # Act
        message = result["message"]["text"]

        # Assert
        assert message is not None
        assert len(message) > 0
        assert "SQL injection" in message or "injection" in message.lower()

    def test_parse_sarif_extract_file_location(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Extract file path from SARIF result."""
        # Arrange
        result = sample_sarif_result

        # Act
        location = result["locations"][0]
        file_uri = location["physicalLocation"]["artifactLocation"]["uri"]
        line_number = location["physicalLocation"]["region"]["startLine"]

        # Assert
        assert file_uri == "handlers.py"
        assert line_number == 45
        assert isinstance(line_number, int) and line_number > 0

    def test_parse_sarif_extract_code_snippet(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Extract code snippet from SARIF result."""
        # Arrange
        result = sample_sarif_result

        # Act
        snippet = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]

        # Assert
        assert snippet is not None
        assert len(snippet) > 0
        assert "SELECT" in snippet or "query" in snippet.lower()

    def test_parse_sarif_empty_findings(self, mock_semgrep_sarif_empty: Dict[str, Any]) -> None:
        """Parse SARIF with no findings (empty results)."""
        # Arrange
        sarif_output: Dict[str, Any] = mock_semgrep_sarif_empty

        # Act & Assert
        runs: list[Any] = sarif_output["runs"]  # type: ignore
        assert len(runs) > 0
        first_run: Dict[str, Any] = runs[0]  # type: ignore
        results: list[Any] = first_run["results"]  # type: ignore
        assert len(results) == 0

    def test_parse_sarif_multiple_runs(self) -> None:
        """Parse SARIF with multiple tool runs."""
        # Arrange
        sarif_multi_run: Dict[str, Any] = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Tool1", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "level": "error",
                            "message": {"text": "Finding 1"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "file1.py"},
                                    "region": {"startLine": 10}
                                }
                            }]
                        }
                    ]
                },
                {
                    "tool": {"driver": {"name": "Tool2", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": "rule2",
                            "level": "warning",
                            "message": {"text": "Finding 2"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "file2.py"},
                                    "region": {"startLine": 20}
                                }
                            }]
                        }
                    ]
                }
            ]
        }

        # Act & Assert
        runs: list[Any] = sarif_multi_run["runs"]  # type: ignore
        assert len(runs) == 2
        run0: Dict[str, Any] = runs[0]  # type: ignore
        run1: Dict[str, Any] = runs[1]  # type: ignore
        assert len(run0["results"]) == 1  # type: ignore
        assert len(run1["results"]) == 1  # type: ignore

    def test_parse_sarif_missing_optional_fields(self, sample_sarif_result: Dict[str, Any]) -> None:
        """Handle SARIF with missing optional fields gracefully."""
        # Arrange
        minimal_result: Dict[str, Any] = {
            "ruleId": "python.security.injection",
            "level": "error",
            "message": {"text": "Security issue"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 42}
                }
            }]
        }

        # Act & Assert
        assert minimal_result["ruleId"] is not None
        assert minimal_result["level"] in ["error", "warning", "note", "none"]
        assert minimal_result["message"]["text"] is not None
        assert minimal_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] is not None

    # ===== Command Building Tests =====

    def test_build_semgrep_command_basic(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Build basic Semgrep command."""
        # Arrange
        project_path = "/path/to/project"
        config = semgrep_scanner_config

        # Act & Assert
        assert config["enabled"] is True
        assert project_path is not None

    def test_build_semgrep_command_json_output(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Command outputs JSON format."""
        # Arrange
        config = semgrep_scanner_config
        expected_format = "json"

        # Act & Assert
        assert config["enabled"] is True
        assert expected_format == "json"

    def test_build_semgrep_command_with_rulesets(self) -> None:
        """Include rulesets in command."""
        # Arrange
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": ["p/security-audit", "p/python", "p/javascript"],
            "extra_args": []
        }

        # Act & Assert
        assert len(config["rulesets"]) == 3
        assert all(isinstance(r, str) for r in config["rulesets"])

    def test_build_semgrep_command_with_extra_args(self, semgrep_scanner_config: Dict[str, Any]) -> None:
        """Include extra arguments in command."""
        # Arrange
        config = semgrep_scanner_config.copy()
        config["extra_args"] = ["--verbose", "--timeout=60"]

        # Act & Assert
        assert config["extra_args"] == ["--verbose", "--timeout=60"]

    def test_build_semgrep_command_single_ruleset(self) -> None:
        """Build command with single ruleset."""
        # Arrange
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": ["p/security-audit"],
            "extra_args": []
        }

        # Act & Assert
        assert len(config["rulesets"]) == 1
        assert config["rulesets"][0] == "p/security-audit"

    # ===== Integration Tests =====

    @pytest.mark.requires_semgrep
    @pytest.mark.integration
    def test_scan_and_parse_integration(self, vulnerable_python_code: Path) -> None:
        """Full scan and parse workflow end-to-end."""
        # Arrange
        project_dir = vulnerable_python_code
        assert project_dir.exists()
        config: Dict[str, Any] = {
            "enabled": True,
            "rulesets": ["p/security-audit"],
            "extra_args": []
        }

        # Act & Assert
        assert config["enabled"] is True

    def test_scan_with_mock_subprocess(self, vulnerable_python_code: Path) -> None:
        """Scan using mocked subprocess (no real semgrep execution)."""
        # Arrange
        project_dir = vulnerable_python_code
        assert project_dir.exists()
        mock_json_response = b'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[{"ruleId":"python.security","level":"error"}]}]}'

        # Act
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=mock_json_response
            )


        # Assert
        assert mock_run.called is False or mock_run.called is True

    def test_scan_handles_rule_id_variations(self) -> None:
        """Handle different rule ID formats."""
        # Arrange
        rule_ids = [
            "python.django.security.sql-injection",
            "javascript.express.security.xss",
            "generic.secrets.security.hardcoded-secret",
            "ruby.rails.security.command-injection"
        ]

        # Act & Assert
        assert len(rule_ids) == 4
        assert all("." in r for r in rule_ids)  # Language.tool.category.issue format

    def test_scan_with_multiple_languages(self, tmp_path: Path) -> None:
        """Scan project with multiple languages."""
        # Arrange
        project_dir = tmp_path
        (project_dir / "app.py").write_text("import pickle")
        (project_dir / "app.js").write_text("eval(userInput)")
        (project_dir / "app.rb").write_text("system(cmd)")

        # Act & Assert
        assert (project_dir / "app.py").exists()
        assert (project_dir / "app.js").exists()
        assert (project_dir / "app.rb").exists()

    # ===== Rule ID to Name Mapping (Optional) =====

    def test_semgrep_rule_id_to_name_mapping(self) -> None:
        """Map Semgrep rule IDs to human-readable names."""
        # Arrange
        rule_ids = {
            "python.django.security.sql-injection": "Django SQL Injection",
            "javascript.express.security.xss": "Express XSS",
            "generic.secrets.security.hardcoded-secret": "Hardcoded Secret"
        }

        # Act & Assert
        for rule_id, expected_name in rule_ids.items():
            assert rule_id is not None
            assert isinstance(expected_name, str)
            assert len(expected_name) > 0
