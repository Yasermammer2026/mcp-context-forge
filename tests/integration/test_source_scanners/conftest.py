# -*- coding: utf-8 -*-
"""Pytest configuration and fixtures for Semgrep runner integration tests.

Comprehensive fixtures for integration testing including:
- Temporary directories for cloned repositories
- SemgrepRunner instances with various configurations
- Mock SARIF/JSON outputs for all scenarios
- Real GitHub repository URLs for live testing
- Async/await test support
- Authentication fixtures (GitHub token, SSH key)
- Cache and timeout handling
- Helper utilities for Finding validation
"""

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Generator, Literal, Optional, Coroutine

import pytest

from plugins.source_scanner.scanners.semgrep_runner import SemgrepRunner
from plugins.source_scanner.types import Finding

logger = logging.getLogger(__name__)


# Constants

SEMGREP_TIMEOUT_DEFAULT = 300  # 5 minutes
SEMGREP_TIMEOUT_EXTENDED = 900  # 15 minutes for slow systems
REPO_CLONE_TIMEOUT = 120  # 2 minutes
MAX_REPO_SIZE_MB = 500
TEST_MARKER_REQUIRES_SEMGREP = "requires_semgrep"
TEST_MARKER_REQUIRES_NETWORK = "requires_network"
TEST_MARKER_SLOW = "slow"
TEST_MARKER_INTEGRATION = "integration"


# Utility Functions

def is_semgrep_installed() -> bool:
    """Check if semgrep is installed and accessible.
    
    Returns:
        bool: True if semgrep is in PATH and executable
    """
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_git_version() -> Optional[str]:
    """Get installed Git version if available.
    
    Returns:
        Optional[str]: Git version string or None if not installed
    """
    try:
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


# Pytest Hooks & Configuration

def pytest_configure(config: pytest.Config) -> None:
    """Register custom pytest markers and initialize logging.
    
    Markers:
    - requires_semgrep: Test needs semgrep installation
    - requires_network: Test needs internet access
    - slow: Test is slow (real clones/scans)
    - integration: Integration test vs unit test
    
    Args:
        config: pytest config object
    """
    config.addinivalue_line(
        "markers",
        f"{TEST_MARKER_REQUIRES_SEMGREP}: mark test as requiring semgrep installation",
    )
    config.addinivalue_line(
        "markers",
        f"{TEST_MARKER_REQUIRES_NETWORK}: mark test as requiring internet access (GitHub)",
    )
    config.addinivalue_line(
        "markers",
        f"{TEST_MARKER_SLOW}: mark test as slow (e.g., real repo cloning)",
    )
    config.addinivalue_line(
        "markers",
        f"{TEST_MARKER_INTEGRATION}: mark test as integration test (not unit)",
    )
    
    if is_semgrep_installed():
        logger.info("✓ Semgrep is installed and available")
    else:
        logger.warning("✗ Semgrep not found - some tests will be skipped")
    
    git_version = get_git_version()
    if git_version:
        logger.info(f"✓ Git available: {git_version}")
    else:
        logger.warning("✗ Git not found - repository cloning tests will be skipped")


# Fixtures: Temporary Directories

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create and cleanup a temporary directory for each test.
    
    Properly handles cleanup even on test failure.
    
    Yields:
        Path: Temporary directory path
        
    Cleanup:
        Removes directory and all contents after test
    """
    temp_path = Path(tempfile.mkdtemp(prefix="semgrep_test_"))
    logger.debug(f"Created temp directory: {temp_path}")
    try:
        yield temp_path
    finally:
        if temp_path.exists():
            try:
                shutil.rmtree(temp_path, ignore_errors=False)
                logger.debug(f"Cleaned up temp directory: {temp_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_path}: {e}")


@pytest.fixture
def repo_clone_dir() -> Generator[Path, None, None]:
    """Create temporary directory specifically for cloned repositories.
    
    Used by integration tests that clone real MCP repos.
    Ensures separate cleanup from general temp files.
    
    Yields:
        Path: Directory for cloning repos
        
    Cleanup:
        Removes directory and all cloned contents after test
    """
    clone_dir = Path(tempfile.mkdtemp(prefix="semgrep_clone_"))
    logger.debug(f"Created clone directory: {clone_dir}")
    try:
        yield clone_dir
    finally:
        if clone_dir.exists():
            try:
                shutil.rmtree(clone_dir, ignore_errors=False)
                logger.debug(f"Cleaned up clone directory: {clone_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup clone directory {clone_dir}: {e}")


@pytest.fixture
def scan_output_dir() -> Generator[Path, None, None]:
    """Create temporary directory for scan outputs and reports.
    
    Yields:
        Path: Directory for storing scan results
    """
    output_dir = Path(tempfile.mkdtemp(prefix="semgrep_output_"))
    logger.debug(f"Created output directory: {output_dir}")
    try:
        yield output_dir
    finally:
        if output_dir.exists():
            try:
                shutil.rmtree(output_dir, ignore_errors=False)
            except Exception as e:
                logger.warning(f"Failed to cleanup output directory: {e}")


# Fixtures: SemgrepRunner Configuration

@pytest.fixture
def semgrep_config_basic() -> dict[str, Any]:
    """Basic Semgrep configuration for testing.
    
    Uses default rulesets and minimal args.
    Good for quick smoke tests.
    
    Returns:
        dict: Config matching SemgrepRunner.__init__ expectations
    """
    return {
        "enabled": True,
        "rulesets": ["p/security-audit"],
        "extra_args": [],
        "timeout": SEMGREP_TIMEOUT_DEFAULT,
    }


@pytest.fixture
def semgrep_config_verbose() -> dict[str, Any]:
    """Comprehensive Semgrep configuration with multiple rulesets.
    
    Includes security audit, OWASP Top 10, and language-specific rules.
    Tests compatibility with multiple ruleset configurations.
    
    Returns:
        dict: Config with OWASP and language-specific rulesets
    """
    return {
        "enabled": True,
        "rulesets": [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/python",
            "p/javascript",
        ],
        "extra_args": ["--verbose"],
        "timeout": SEMGREP_TIMEOUT_EXTENDED,
    }


@pytest.fixture
def semgrep_config_custom_timeout() -> dict[str, Any]:
    """Semgrep configuration with extended timeout for slow systems.
    
    Useful for CI/CD environments or resource-constrained testing.
    
    Returns:
        dict: Config with 15-minute timeout
    """
    return {
        "enabled": True,
        "rulesets": ["p/security-audit"],
        "extra_args": [],
        "timeout": SEMGREP_TIMEOUT_EXTENDED,
    }


@pytest.fixture
def semgrep_config_minimal() -> dict[str, Any]:
    """Minimal Semgrep configuration (almost empty).
    
    Tests that defaults are properly applied when config is sparse.
    
    Returns:
        dict: Config with only enabled flag
    """
    return {"enabled": True}


@pytest.fixture
def semgrep_config_disabled() -> dict[str, Any]:
    """Configuration with scanner disabled.
    
    Tests proper handling of disabled scanners.
    
    Returns:
        dict: Config with enabled=False
    """
    return {
        "enabled": False,
        "rulesets": ["p/security-audit"],
        "timeout": 300,
    }


@pytest.fixture
def semgrep_runner_basic(semgrep_config_basic: dict[str, Any]) -> SemgrepRunner:
    """Create basic SemgrepRunner instance for smoke tests.
    
    Args:
        semgrep_config_basic: Fixture providing basic config
        
    Returns:
        SemgrepRunner: Configured runner instance
    """
    return SemgrepRunner(semgrep_config_basic)


@pytest.fixture
def semgrep_runner_verbose(semgrep_config_verbose: dict[str, Any]) -> SemgrepRunner:
    """Create comprehensive SemgrepRunner for full vulnerability testing.
    
    Args:
        semgrep_config_verbose: Fixture with multiple rulesets
        
    Returns:
        SemgrepRunner: Configured runner instance
    """
    return SemgrepRunner(semgrep_config_verbose)


@pytest.fixture
def semgrep_runner_custom_timeout(semgrep_config_custom_timeout: dict[str, Any]) -> SemgrepRunner:
    """Create SemgrepRunner with extended timeout.
    
    Args:
        semgrep_config_custom_timeout: Fixture with 15-min timeout
        
    Returns:
        SemgrepRunner: Configured runner instance
    """
    return SemgrepRunner(semgrep_config_custom_timeout)


# Fixtures: Mock SARIF/JSON Outputs

@pytest.fixture
def mock_sarif_empty() -> dict[str, Any]:
    """Mock SARIF: empty results (clean code).
    
    Reflects: semgrep scan with no vulnerabilities found.
    
    Returns:
        dict: Empty results list
    """
    return {"results": []}


@pytest.fixture
def mock_sarif_single_finding() -> dict[str, Any]:
    """Mock SARIF: one critical finding (SQL injection).
    
    Reflects: Real-world vulnerability that should be caught.
    
    Returns:
        dict: SARIF with single ERROR severity finding
    """
    return {
        "results": [
            {
                "check_id": "python.django.security.sql-injection",
                "severity": "ERROR",
                "message": "SQL injection vulnerability",
                "path": "handlers.py",
                "start": {"line": 45, "col": 20},
                "extra": {
                    "message": "Detected SQL injection via string concatenation",
                    "lines": 'query = f"SELECT * FROM users WHERE id={uid}"',
                    "doc_url": "https://semgrep.dev/r/python.django.security.sql-injection",
                },
            }
        ]
    }


@pytest.fixture
def mock_sarif_multiple_findings() -> dict[str, Any]:
    """Mock SARIF: multiple findings with varying severity.
    
    Reflects: Real scan of vulnerable code (CRITICAL, HIGH, MEDIUM).
    Tests severity mapping and multiple finding handling.
    
    Returns:
        dict: SARIF with 3 findings of different severity levels
    """
    return {
        "results": [
            {
                "check_id": "python.django.security.sql-injection",
                "severity": "ERROR",
                "message": "SQL injection via string concatenation",
                "path": "app/handlers.py",
                "start": {"line": 45, "col": 20},
                "extra": {
                    "message": "Use parameterized queries",
                    "lines": 'query = f"SELECT * FROM users WHERE id={uid}"',
                    "doc_url": "https://semgrep.dev/r/sql-injection",
                },
            },
            {
                "check_id": "python.lang.security.deserialization",
                "severity": "HIGH",
                "message": "Unsafe deserialization",
                "path": "app/utils.py",
                "start": {"line": 102, "col": 5},
                "extra": {
                    "message": "Use json.loads instead of pickle",
                    "lines": "data = pickle.loads(user_input)",
                    "doc_url": "https://semgrep.dev/r/deserialization",
                },
            },
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
                "severity": "MEDIUM",
                "message": "Hardcoded password detected",
                "path": "config.py",
                "start": {"line": 8, "col": 1},
                "extra": {
                    "message": "Use environment variables for secrets",
                    "lines": 'PASSWORD = "supersecret123"',
                    "doc_url": "https://semgrep.dev/r/hardcoded-password",
                },
            },
        ]
    }


@pytest.fixture
def mock_sarif_with_error() -> dict[str, Any]:
    """Mock SARIF: error during scanning (timeout, permissions, etc).
    
    Reflects: Semgrep failure cases.
    Tests error handling path in parser.
    
    Returns:
        dict: Output with error field instead of results
    """
    return {"error": "Semgrep execution timeout exceeded"}


@pytest.fixture
def mock_sarif_missing_fields() -> dict[str, Any]:
    """Mock SARIF: sparse/minimal finding (missing optional fields).
    
    Reflects: Edge case where optional fields are not present.
    Tests null handling in Finding object creation.
    
    Returns:
        dict: SARIF with minimal required fields only
    """
    return {
        "results": [
            {
                "check_id": "rule.minimal",
                "severity": "INFO",
                "message": "Minor issue",
                "path": "file.py",
                "start": {},
            }
        ]
    }


@pytest.fixture
def mock_sarif_null_values() -> dict[str, Any]:
    """Mock SARIF: findings with null/None values in fields.
    
    Reflects: Edge case of incomplete SARIF output.
    Tests robust handling of null values.
    
    Returns:
        dict: SARIF with None values
    """
    return {
        "results": [
            {
                "check_id": "rule.nulls",
                "severity": "INFO",
                "message": "Test with nulls",
                "path": "file.py",
                "start": {"line": 10, "col": None},
                "extra": {
                    "message": None,
                    "doc_url": None,
                },
            }
        ]
    }


# Fixtures: Authentication & Git Configuration

@pytest.fixture
def github_token() -> str:
    """GitHub authentication token for private repo testing.
    
    Can be overridden with GITHUB_TOKEN environment variable.
    Used to test authenticated cloning of private repositories.
    
    Returns:
        str: GitHub token (empty if not configured)
    """
    token = os.getenv("GITHUB_TOKEN", "")
    if token:
        logger.debug("GitHub token configured")
    return token


@pytest.fixture
def ssh_config() -> dict[str, Any]:
    """SSH configuration for repository access.
    
    Contains path to SSH key for Git operations.
    Can be overridden with SSH_KEY_PATH environment variable.
    
    Returns:
        dict: SSH configuration
    """
    ssh_key_path = os.getenv("SSH_KEY_PATH", "")
    return {
        "ssh_enabled": bool(ssh_key_path),
        "ssh_key_path": ssh_key_path,
    }


@pytest.fixture
def semgrep_config_with_auth(
    semgrep_config_basic: dict[str, Any], github_token: str, ssh_config: dict[str, Any]
) -> dict[str, Any]:
    """Semgrep configuration extended with authentication details.
    
    Combines base config with auth fixtures.
    Used for testing authenticated repository access.
    
    Args:
        semgrep_config_basic: Base configuration
        github_token: GitHub token fixture
        ssh_config: SSH configuration fixture
        
    Returns:
        dict: Extended config with auth fields
    """
    config = semgrep_config_basic.copy()
    config.update({
        "github_token": github_token,
        "ssh_config": ssh_config,
    })
    return config


# Fixtures: Real Repository URLs

@pytest.fixture(scope="session")
def real_github_python_vulnerable() -> str:
    """Real vulnerable Python repository (OWASP WebGoat-Python).
    
    Contains intentionally vulnerable Python code for security learning.
    Used to verify Semgrep/Bandit detection of Python vulnerabilities.
    
    Markers: @pytest.mark.requires_network, @pytest.mark.slow
    
    Returns:
        str: HTTPS URL to vulnerable Python repo
    """
    url = "https://github.com/OWASP/WebGoat-Python.git"
    logger.info(f"Real vulnerable Python repo: {url}")
    return url


@pytest.fixture(scope="session")
def real_github_js_vulnerable() -> str:
    """Real vulnerable JavaScript repository (Juice Shop).
    
    Contains intentionally vulnerable web app written in Node.js.
    Used to verify Semgrep detection of JavaScript vulnerabilities.
    
    Markers: @pytest.mark.requires_network, @pytest.mark.slow
    
    Returns:
        str: HTTPS URL to vulnerable JS repo
    """
    url = "https://github.com/juice-shop/juice-shop.git"
    logger.info(f"Real vulnerable JS repo: {url}")
    return url


@pytest.fixture(scope="session")
def real_github_python_clean() -> str:
    """Real well-maintained Python repository (Python requests library).
    
    Generally clean code with minimal security issues.
    Used for negative testing (should find few or no critical issues).
    
    Markers: @pytest.mark.requires_network, @pytest.mark.slow
    
    Returns:
        str: HTTPS URL to well-maintained repo
    """
    url = "https://github.com/psf/requests.git"
    logger.info(f"Real clean Python repo: {url}")
    return url


@pytest.fixture(scope="session")
def mcp_test_repo() -> str:
    """MCP Python SDK repository from Anthropic.
    
    The primary test repository for MCP integration testing.
    Can be overridden via TEST_MCP_REPO_URL environment variable.
    
    Markers: @pytest.mark.requires_network, @pytest.mark.slow
    
    Returns:
        str: HTTPS URL to MCP test repository
        
    Example:
        export TEST_MCP_REPO_URL="https://github.com/your-org/mcp-server.git"
        pytest tests/integration/test_source_scanners/
    """
    url = os.getenv(
        "TEST_MCP_REPO_URL",
        "https://github.com/modelcontextprotocol/python-sdk.git",
    )
    logger.info(f"MCP test repo: {url}")
    return url


# Fixtures: Async Support

@pytest.fixture
def event_loop():
    """Provide asyncio event loop for async tests.
    
    Required for @pytest.mark.asyncio tests.
    Creates new loop scoped to test function.
    
    Requires: pytest-asyncio plugin
    
    Yields:
        asyncio.AbstractEventLoop: Event loop for this test
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


# Fixtures: Timeout Simulation & Cache Testing

@pytest.fixture
def mock_slow_semgrep(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Coroutine[Any, Any, Any]]:
    """Simulate slow Semgrep execution (for timeout testing).
    
    Patches run_command to simulate timeout behavior.
    Used to test timeout handling without actual delays.
    
    Args:
        monkeypatch: pytest monkeypatch fixture
        
    Returns:
        callable: Patching function (already applied)
    """
    async def slow_run_command(cmd: str, *args: Any, **kwargs: Any) -> Any:
        return type(
            "Result",
            (),
            {"returncode": 124, "stdout": "", "stderr": "timeout"},
        )()
    
    monkeypatch.setattr(
        "plugins.source_scanner.scanners.semgrep_runner.run_command",
        slow_run_command,
    )
    return slow_run_command


@pytest.fixture
def mock_cache_entry() -> dict[str, Any]:
    """Mock cached scan result.
    
    Simulates previously cached scan for same repo/commit.
    Used to test cache hit/miss scenarios.
    
    Returns:
        dict: Cached assessment with findings
    """
    return {
        "assessment_id": 42,
        "git_commit_sha": "abc123def456",
        "scan_timestamp": "2024-02-15T10:30:00Z",
        "findings": [
            {
                "rule_id": "python.django.security.sql-injection",
                "severity": "ERROR",
                "file_path": "handlers.py",
                "line": 45,
            }
        ],
        "scan_duration_seconds": 12.5,
    }


@pytest.fixture
def repo_metadata() -> dict[str, Any]:
    """Repository metadata for testing Git operations.
    
    Contains branch, tag, commit information.
    Used for testing selective cloning/checkout.
    
    Returns:
        dict: Repository metadata (local structure, no network call)
    """
    return {
        "default_branch": "main",
        "branches": ["main", "develop", "feature/security"],
        "tags": ["v1.0.0", "v1.1.0", "v2.0.0"],
        "latest_commit": "abc123def456",
        "commit_message": "fix: resolve SQL injection vulnerability",
    }


# Fixtures: Utility Helpers for Test Data & Validation

@pytest.fixture
def create_mock_finding() -> Callable[..., Finding]:
    """Factory fixture for creating mock Finding objects with defaults.
    
    Useful for building Finding instances in tests without boilerplate.
    
    Returns:
        Callable: Function to create Finding instances
        
    Example:
        finding = create_mock_finding(
            rule_id="custom.rule",
            severity="WARNING",
            line=99
        )
    """
    
    def _create_finding(
        scanner: str = "semgrep",
        rule_id: str = "test.rule.id",
        severity: Literal["ERROR", "WARNING", "INFO"] = "INFO",
        message: str = "Test finding",
        file_path: str = "test.py",
        line: Optional[int] = 1,
        column: Optional[int] = None,
        code_snippet: Optional[str] = None,
        help_url: Optional[str] = None,
    ) -> Finding:
        """Create a Finding instance.
        
        Args:
            scanner: Scanner name (e.g., "semgrep", "bandit")
            rule_id: Rule identifier (e.g., "python.lang.security.sql-injection")
            severity: Severity level (ERROR, WARNING, INFO)
            message: Human-readable message
            file_path: Path to vulnerable file
            line: Line number of issue
            column: Column number (optional)
            code_snippet: Code context (optional)
            help_url: Documentation link (optional)
            
        Returns:
            Finding: Configured Finding object
        """
        return Finding(
            scanner=scanner,
            rule_id=rule_id,
            severity=severity,
            message=message,
            file_path=file_path,
            line=line,
            column=column,
            code_snippet=code_snippet,
            help_url=help_url,
        )
    
    return _create_finding


@pytest.fixture
def assert_finding_fields() -> Callable[[Finding], None]:
    """Helper to validate all required Finding fields are present.
    
    Useful for comprehensive Finding object validation in tests.
    
    Returns:
        Callable: Assertion function
        
    Example:
        assert_finding_fields(finding)  # Passes if all fields present
    """
    
    def _assert_fields(finding: Finding) -> None:
        """Assert all fields exist on Finding object.
        
        Args:
            finding: Finding object to validate
            
        Raises:
            AssertionError: If any required field is missing
        """
        required_fields = [
            "scanner",
            "rule_id",
            "severity",
            "message",
            "file_path",
            "line",
            "column",
            "code_snippet",
            "help_url",
        ]
        for field in required_fields:
            assert hasattr(
                finding, field
            ), f"Missing required field: {field}"
    
    return _assert_fields


@pytest.fixture
def assert_valid_severity() -> Callable[[str], None]:
    """Helper to validate severity level is in expected range.
    
    Returns:
        Callable: Validation function
    """
    valid_severities = ["ERROR", "WARNING", "INFO"]
    
    def _assert_severity(severity: str) -> None:
        """Assert severity is in valid set.
        
        Args:
            severity: Severity string to validate
            
        Raises:
            AssertionError: If severity not in valid set
        """
        assert severity in valid_severities, (
            f"Invalid severity '{severity}'. "
            f"Must be one of: {', '.join(valid_severities)}"
        )
    
    return _assert_severity


@pytest.fixture(autouse=True)
def log_test_info(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Automatically log test name and status (autouse fixture).
    
    Logs at start and completion of each test.
    Helps with debugging test execution flow.
    
    Args:
        request: pytest request object
        
    Yields:
        None
    """
    test_name: str = request.node.name  # type: ignore[attr-defined]
    logger.info(f"🧪 Starting: {test_name}")
    yield
    logger.info(f"✓ Completed: {test_name}")
