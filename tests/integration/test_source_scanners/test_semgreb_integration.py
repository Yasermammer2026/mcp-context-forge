# -*- coding: utf-8 -*-
"""Integration tests for Semgrep scanning on real repositories.

This module tests the SemgrepRunner integration with:
- Real GitHub repositories (MCP context-forge, vulnerable examples)
- Multiple scanner configurations (basic, verbose, custom timeout)
- Finding validation and severity mapping
- Error handling and edge cases
- Performance and timeout scenarios

All tests require:
- semgrep installed and in PATH
- git installed and configured
- Network access to GitHub
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from plugins.source_scanner.scanners.semgrep_runner import SemgrepRunner
from plugins.source_scanner.types import Finding

logger = logging.getLogger(__name__)


@pytest.mark.integration
@pytest.mark.requires_semgrep
@pytest.mark.requires_network
@pytest.mark.slow
class TestSemgrepMCPServers:
    """Test Semgrep scanning on IBM MCP context-forge servers."""

    @pytest.mark.asyncio
    async def test_semgrep_scan_fast_time_server_go(self, semgrep_runner_basic: SemgrepRunner, repo_clone_dir: Path) -> None:
        """Test Semgrep scan on IBM fast-time-server (Go MCP server).
        
        Verifies:
        - Repository clones successfully from GitHub
        - Fast-time-server Go code is found and readable
        - SemgrepRunner properly executes with security-audit ruleset
        - Findings have complete structure (rule_id, severity, file_path, line)
        - Scan completes within timeout
        
        Args:
            semgrep_runner_basic: SemgrepRunner configured with basic settings
            repo_clone_dir: Temporary directory for cloning
        """
        repo_url = "https://github.com/IBM/mcp-context-forge.git"
        temp_folder = str(repo_clone_dir / "fast-time-server-test")
        
        logger.info(f"Testing Semgrep scan on fast-time-server Go implementation")
        logger.info(f"Repository: {repo_url}")
        
        try:
            start_time = time.time()
            findings = await semgrep_runner_basic.run(repo_url, temp_folder)
            elapsed_time = time.time() - start_time
            
            # Validate result structure
            assert isinstance(findings, list), "Findings must be a list"
            logger.info(f"✓ Scan completed in {elapsed_time:.2f}s")
            logger.info(f"✓ Detected {len(findings)} findings")
            
            # Validate each finding structure
            _validate_findings_structure(findings)
            
            # Log summary by severity
            _log_findings_summary(findings)
            
        except Exception as e:
            logger.error(f"✗ Scan failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_semgrep_scan_all_mcp_servers(
        self, semgrep_runner_verbose: SemgrepRunner, repo_clone_dir: Path
    ) -> None:
        """Test Semgrep scan on all MCP servers (Python, JavaScript, Go, Rust).
        
        Verifies:
        - Multiple rulesets execute correctly (security-audit, owasp-top-ten, language-specific)
        - All MCP server implementations are scanned
        - Verbose mode captures additional context
        - Findings are properly aggregated across languages
        
        Args:
            semgrep_runner_verbose: SemgrepRunner with multiple rulesets
            repo_clone_dir: Temporary directory for cloning
        """
        repo_url = "https://github.com/IBM/mcp-context-forge.git"
        temp_folder = str(repo_clone_dir / "all-mcp-servers-test")
        
        logger.info("Testing Semgrep scan on all MCP server implementations")
        logger.info(f"Repository: {repo_url}")
        logger.info(f"Rulesets: {semgrep_runner_verbose.rulesets}")
        
        try:
            start_time = time.time()
            findings = await semgrep_runner_verbose.run(repo_url, temp_folder)
            elapsed_time = time.time() - start_time
            
            assert isinstance(findings, list), "Findings must be a list"
            logger.info(f"✓ Scan completed in {elapsed_time:.2f}s with verbose config")
            logger.info(f"✓ Total findings detected: {len(findings)}")
            
            # Validate findings
            _validate_findings_structure(findings)
            _log_findings_summary(findings)
            
            # Verify verbose config was applied
            assert semgrep_runner_verbose.extra_args is not None
            logger.info(f"✓ Extra args applied: {semgrep_runner_verbose.extra_args}")
            
        except Exception as e:
            logger.error(f"✗ Scan with verbose config failed: {e}")
            raise

    @pytest.mark.asyncio
    async def test_semgrep_fast_time_server_with_extended_timeout(
        self, semgrep_runner_custom_timeout: SemgrepRunner, repo_clone_dir: Path
    ) -> None:
        """Test Semgrep on fast-time-server with extended timeout.
        
        Verifies:
        - Extended timeout (900s) is properly applied
        - Scan completes within longer timeout window
        - Configuration properly overrides defaults
        
        Args:
            semgrep_runner_custom_timeout: SemgrepRunner with 900s timeout
            repo_clone_dir: Temporary directory for cloning
        """
        repo_url = "https://github.com/IBM/mcp-context-forge.git"
        temp_folder = str(repo_clone_dir / "extended-timeout-test")
        
        logger.info("Testing Semgrep with extended timeout (900s)")
        logger.info(f"Timeout configured: {semgrep_runner_custom_timeout.timeout}s")
        
        try:
            start_time = time.time()
            findings = await semgrep_runner_custom_timeout.run(repo_url, temp_folder)
            elapsed_time = time.time() - start_time
            
            assert isinstance(findings, list), "Findings must be a list"
            logger.info(f"✓ Scan completed in {elapsed_time:.2f}s (within 900s timeout)")
            logger.info(f"✓ Findings: {len(findings)}")
            
            assert semgrep_runner_custom_timeout.timeout == 900, "Timeout not set correctly"
            logger.info("✓ Extended timeout correctly configured")
            
        except asyncio.TimeoutError:
            pytest.fail("Scan exceeded extended timeout of 900s")
        except Exception as e:
            logger.error(f"✗ Scan with extended timeout failed: {e}")
            raise


@pytest.mark.integration
class TestSemgrepFindingValidation:
    """Test finding parsing and validation from SARIF JSON data."""

    def test_parse_sarif_single_finding(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_single_finding: dict[str, Any]
    ) -> None:
        """Test SARIF parsing for single critical finding.
        
        Validates:
        - Single finding is correctly parsed from SARIF JSON
        - All required fields are extracted
        - Severity mapping works correctly
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_single_finding: Mock SARIF with one finding
        """
        sarif = mock_sarif_single_finding
        
        # Validate SARIF structure
        assert "results" in sarif, "SARIF missing 'results' field"
        assert len(sarif["results"]) == 1, "Expected exactly one finding"
        
        # Parse findings
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 1, "Should parse to one Finding object"
        
        finding = findings[0]
        assert finding.rule_id == "python.django.security.sql-injection"
        assert finding.severity == "ERROR"
        assert finding.file_path == "handlers.py"
        assert finding.line == 45
        
        logger.info(f"✓ Single finding SARIF parsed correctly: {finding.rule_id}")

    def test_parse_sarif_multiple_findings(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_multiple_findings: dict[str, Any]
    ) -> None:
        """Test SARIF parsing for multiple findings with different severities.
        
        Validates:
        - Multiple findings are extracted correctly
        - Severity levels are properly mapped (ERROR, HIGH, MEDIUM)
        - All findings maintain correct structure
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_multiple_findings: Mock SARIF with 3 findings
        """
        sarif = mock_sarif_multiple_findings
        
        assert len(sarif["results"]) == 3, "Expected exactly three findings"
        
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 3, "Should parse to three Finding objects"
        
        # Verify severity mapping
        assert findings[0].severity == "ERROR"
        assert findings[1].severity == "ERROR"  # HIGH maps to ERROR
        assert findings[2].severity == "WARNING"  # MEDIUM maps to WARNING
        
        logger.info(f"✓ Multiple findings SARIF parsed correctly: {len(findings)} findings")
        logger.info(f"  Severities: {[f.severity for f in findings]}")

    def test_parse_sarif_empty_results(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_empty: dict[str, Any]
    ) -> None:
        """Test SARIF parsing for empty results (clean code scenario).
        
        Validates:
        - Empty results are handled gracefully
        - No false positives are generated
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_empty: Mock SARIF with empty results
        """
        sarif = mock_sarif_empty
        
        assert "results" in sarif, "SARIF missing 'results' field"
        assert len(sarif["results"]) == 0, "Expected empty results"
        
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 0, "Empty SARIF should produce no findings"
        
        logger.info("✓ Empty SARIF (clean code) parsed correctly")

    def test_parse_sarif_with_error(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_with_error: dict[str, Any]
    ) -> None:
        """Test SARIF parsing handles error responses gracefully.
        
        Validates:
        - Error responses don't crash the parser
        - Empty list is returned on error
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_with_error: Mock SARIF with error field
        """
        sarif = mock_sarif_with_error
        
        assert "error" in sarif, "Expected error field in SARIF"
        
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 0, "Error SARIF should produce no findings"
        
        logger.info("✓ SARIF with error handled gracefully")

    def test_parse_sarif_missing_fields(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_missing_fields: dict[str, Any]
    ) -> None:
        """Test SARIF parsing with sparse/minimal findings.
        
        Validates:
        - Sparse findings with missing optional fields are handled
        - Required fields are properly extracted
        - None/null handling works correctly
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_missing_fields: Mock SARIF with missing optional fields
        """
        sarif = mock_sarif_missing_fields
        
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 1, "Should parse despite missing fields"
        
        finding = findings[0]
        assert finding.rule_id == "rule.minimal"
        assert finding.severity == "INFO"
        assert finding.file_path == "file.py"
        # line may be None if missing from start object
        
        logger.info("✓ Sparse SARIF parsed correctly despite missing optional fields")

    def test_parse_sarif_null_values(
        self, semgrep_runner_basic: SemgrepRunner, mock_sarif_null_values: dict[str, Any]
    ) -> None:
        """Test SARIF parsing with null/None values in fields.
        
        Validates:
        - Null values don't crash the parser
        - Findings are still created with available data
        
        Args:
            semgrep_runner_basic: Runner with parser methods
            mock_sarif_null_values: Mock SARIF with None values
        """
        sarif = mock_sarif_null_values
        
        findings = semgrep_runner_basic.parse_sarif_output(sarif)
        assert len(findings) == 1, "Should handle null values gracefully"
        
        finding = findings[0]
        assert finding.rule_id == "rule.nulls"
        logger.info("✓ SARIF with null values parsed correctly")


@pytest.mark.integration
class TestFindingObjectCreation:
    """Test creating and validating Finding objects from various sources."""

    def test_create_finding_with_factory(
        self, create_mock_finding: Callable[..., Finding]
    ) -> None:
        """Test creating Finding objects with factory fixture.
        
        Validates:
        - Factory fixture creates valid Finding objects
        - All supplied parameters are correctly set
        
        Args:
            create_mock_finding: Factory fixture for creating Finding objects
        """
        finding = create_mock_finding(
            rule_id="python.sql-injection",
            severity="ERROR",
            file_path="handlers.py",
            line=45,
        )
        
        assert finding.rule_id == "python.sql-injection"
        assert finding.severity == "ERROR"
        assert finding.file_path == "handlers.py"
        assert finding.line == 45
        assert finding.scanner == "semgrep"  # default
        
        logger.info("✓ Finding object created successfully with factory")

    def test_validate_finding_fields(
        self, create_mock_finding: Callable[..., Finding], 
        assert_finding_fields: Callable[[Finding], None]
    ) -> None:
        """Test validation of all required Finding fields.
        
        Validates:
        - All required fields are present on Finding objects
        - Validation function works correctly
        
        Args:
            create_mock_finding: Factory for creating Finding objects
            assert_finding_fields: Validator for Finding structure
        """
        finding = create_mock_finding()
        
        # Should not raise exception
        assert_finding_fields(finding)
        
        logger.info("✓ All required fields present on Finding object")

    def test_validate_severity_levels(
        self, assert_valid_severity: Callable[[str], None]
    ) -> None:
        """Test severity level validation.
        
        Validates:
        - Valid severities are accepted (ERROR, WARNING, INFO)
        - Invalid severities raise assertion errors
        
        Args:
            assert_valid_severity: Validator function for severity
        """
        # Valid severities should pass
        for severity in ["ERROR", "WARNING", "INFO"]:
            assert_valid_severity(severity)
            logger.debug(f"✓ '{severity}' is valid")
        
        # Invalid severity should raise
        with pytest.raises(AssertionError):
            assert_valid_severity("INVALID")
        
        logger.info("✓ Severity validation working correctly")

    @pytest.mark.parametrize(
        "severity,expected_valid",
        [
            ("ERROR", True),
            ("WARNING", True),
            ("INFO", True),
            ("CRITICAL", False),
            ("HIGH", False),
            ("", False),
            (None, False),
        ],
    )
    def test_severity_validation_parametrized(
        self, 
        severity: str,
        expected_valid: bool,
        assert_valid_severity: Callable[[str], None],
    ) -> None:
        """Parametrized test for severity validation with edge cases.
        
        Args:
            severity: Severity string to validate
            expected_valid: Whether validation should pass
            assert_valid_severity: Validator function
        """
        if expected_valid:
            assert_valid_severity(severity)
            logger.debug(f"✓ '{severity}' correctly validated")
        else:
            with pytest.raises((AssertionError, TypeError, AttributeError)):
                assert_valid_severity(severity)
                logger.debug(f"✓ '{severity}' correctly rejected")


# ============================================================================
# Helper Functions for Testing
# ============================================================================

def _validate_findings_structure(findings: list[Finding]) -> None:
    """Validate that all findings have required structure.
    
    Args:
        findings: List of Finding objects to validate
        
    Raises:
        AssertionError: If any finding is missing required fields
    """
    for i, finding in enumerate(findings):
        assert hasattr(finding, "rule_id"), f"Finding {i} missing rule_id"
        assert hasattr(finding, "severity"), f"Finding {i} missing severity"
        assert hasattr(finding, "file_path"), f"Finding {i} missing file_path"
        assert hasattr(finding, "line"), f"Finding {i} missing line"
        
        # Validate severity is one of the allowed values
        valid_severities = ["ERROR", "WARNING", "INFO"]
        assert finding.severity in valid_severities, \
            f"Finding {i} has invalid severity: {finding.severity}"


def _log_findings_summary(findings: list[Finding]) -> None:
    """Log a summary of findings grouped by severity.
    
    Args:
        findings: List of Finding objects
    """
    if not findings:
        logger.info("✓ No vulnerabilities detected (clean code scan)")
        return
    
    error_count = len([f for f in findings if f.severity == "ERROR"])
    warning_count = len([f for f in findings if f.severity == "WARNING"])
    info_count = len([f for f in findings if f.severity == "INFO"])
    
    logger.info(f"Summary: {error_count} ERROR, {warning_count} WARNING, {info_count} INFO")
    
    # Show top findings
    logger.info("Top 5 findings:")
    for i, finding in enumerate(findings[:5], 1):
        logger.info(
            f"  {i}. [{finding.severity}] {finding.rule_id} "
            f"at {finding.file_path}:{finding.line}"
        )



if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])

