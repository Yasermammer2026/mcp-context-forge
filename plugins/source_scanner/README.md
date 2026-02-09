# Source Scanner Plugin

## Purpose
Provides pre-deployment static analysis of MCP server source code using Semgrep and Bandit, with normalized findings stored for policy evaluation. The plugin is designed to run as part of the MCP Gateway pre-registration and pre-deployment hooks, enabling shift-left security checks before MCP servers are added to the runtime or catalog.

## Structure
- `source_scanner.py`: Main plugin class and hooks
- `config.py`: Configuration parsing and normalization
- `policy.py`: Policy evaluation logic
- `repo_fetcher.py`: Git repository cloning and checkout
- `errors.py`: Defines shared exception types used across the plugin
- `language_detector.py`: Detects programming languages used in the target repository
- `types.py`: Defines core data models for the plugin
- `scanners/`: Tool-specific scanner runners (Semgrep, Bandit)
- `parsing/`: Normalizer for scanner outputs
- `storage/`: Persistence layer for scan records (currently SQLAlchemy ORM)
- `utils/`: Execution helpers, subprocess wrappers
- `plugin-manifest.yaml`: Plugin registration
- `Interface_alignment.md` and `design.md`: Design decisions and interface contracts
- `storage/`: SQLAlchemy persistence layer for scan records (used with ScanRepository)

## Status
This is an initial scaffold PR. Functionality is partially implemented; 
Implemented in this PR:
- Plugin skeleton and registration
- Git repository cloning
- Semgrep CLI invocation
- Normalised finding model
- Initial testing

Follow-up PRs will add:
- Admin UI integration
- Bandit integration
- language detection
