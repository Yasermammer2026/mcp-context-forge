# Source Scanner Plugin

## Purpose
Provides pre-deployment static analysis of MCP server source code using Semgrep and Bandit, with normalized findings stored for policy evaluation.

## Structure
- `source_scanner.py`: Main plugin class and hooks
- `config.py`: Configuration parsing and normalization
- `policy.py`: Policy evaluation logic
- `repo_fetcher.py`: Git repository cloning and checkout
- `scanners/`: Tool-specific scanner runners (Semgrep, Bandit)
- `parsing/`: Normalizer for scanner outputs
- `storage/`: Persistence layer for scan records (currently SQLAlchemy ORM)
- `utils/`: Execution helpers, subprocess wrappers
- `plugin-manifest.yaml`: Plugin registration
- `Interface_alignment.md` and `design.md`: Design decisions and interface contracts
- `storage/`: SQLAlchemy persistence layer for scan records (used with ScanRepository)

## Status
This is an initial scaffold PR. Functionality is partially implemented; follow-up PRs will add:
- Admin UI integration
- Bandit integration
