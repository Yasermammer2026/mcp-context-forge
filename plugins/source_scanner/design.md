# SourceScannerPlugin_Design_NotionExport.md

## Flow

Gateway

- **Hook Trigger**  
  The gateway invokes the Source Scanner Plugin during the `server_pre_register` and/or `catalog_pre_deploy` stage.

---

SourceScanner Plugin -> GIT (Clone & Checkout)

- **Source Retrieval**  
  The plugin clones the target Git repository and checks out the specified branch, tag, or commit.

---

SourceScanner Plugin

- **Language Detection**  
  The repository is inspected to identify the project’s primary language(s) and ecosystem.

---

Scanners

- **Scanner Execution**
  - If Python is detected, Bandit is executed to scan the source code.
  - For all supported languages, Semgrep is executed with security-focused rulesets.

---

Scanners -> SourceScanner Plugin

- **Result Collection**  
  Raw scan results are collected from each scanner in their native output formats (e.g. JSON, SARIF).

---

SourceScanner Plugin

- **Merge and Deduplication**  
  Findings from multiple scanners are merged and deduplicated.
- **Policy Evaluation**  
  The aggregated findings are evaluated against configured severity thresholds.

---

SourceScanner Plugin (Resource Cleanup)

- **Resource Cleanup**  
  Temporary directories and other transient resources are cleaned up.

---

SourceScanner Plugin -> Gateway

- **Result Propagation**  
  The final findings or blocking decision are returned to the gateway.

---

### Call Flow

```bash
Gateway
  → SourceScannerPlugin
      → RepoFetcher.fetch(repo_url, ref, auth, limits) → (repo_path, commit_sha, cleanup)
      → LanguageDetector.detect(repo_path) → languages
      → SemgrepRunner.run(repo_path, config, timeout) → findings[]
      → [if python] BanditRunner.run(repo_path, config, timeout) → findings[]
      → ParserNormalizer.merge_dedup(findings_by_scanner) → merged_findings[]
      → PolicyChecker.evaluate(merged_findings, threshold, fail_on_critical) → decision
      → cleanup()
      → return ScanResult(findings, decision, metadata)
```

## Component Responsibilities

- **SourceScannerPlugin**  
  Acts as the orchestrator. It coordinates the scan workflow, reads configuration, and aggregates results.

  **Talks to**
  - Calls `RepoFetcher.fetch(...)`
  - Calls `LanguageDetector.detect(repo_path)`
  - Calls selected `ScannerRunner.run(...)`
  - Calls `ParserNormalizer.merge_dedup(...)`
  - Calls `PolicyChecker.evaluate(...)`
  - Returns `ScanResult` to Gateway

- **RepoFetcher**  
  Handles Git operations, including repository cloning, reference checkout, and temporary directory management.

  - Receives `(repo_url, ref, auth, limits)`
  - Returns `workspace { path, commit_sha }` + `cleanup()`

- **LanguageDetector**  
  Determines the programming language(s) and ecosystem of the repository to guide scanner selection.

  - Receives `repo_path`
  - Returns `languages: string[]`

- **ScannerRunners**  
  Encapsulate the execution logic of individual scanners (e.g. Semgrep, Bandit).

  - Receives `(repo_path, scanner_config, timeout_s)`
  - Returns `findings: Finding[]` (optional `raw_output_ref`)

- **Parser / Normalizer**  
  Parses scanner outputs and converts them into a unified findings schema.

  - Receives `findings_by_scanner: Finding[][]`
  - Returns `merged_findings: Finding[]`

- **Policy / Threshold Checker**  
  Applies severity thresholds and enforcement rules to decide whether to allow or block registration or deployment.

  - Receives `(findings, severity_threshold, fail_on_critical)`
  - Returns `decision { blocked, reason? }`

## Data Contracts (Unified Schemas)

### Finding (Unified Finding Schema)

for each problem from **Scanners**

```bash
- scanner: string                             # from which tool"semgrep" | "bandit" | ...
- severity: "ERROR"|"WARNING"|"INFO"          # used to make policy judgments
- rule_id: string                             # which rule matched (for dedup & explain)
- message: string                             # message for read
- file_path: string                           # which file is the problem in 
- line?: number
- column?: number
- code_snippet?: string
- help_url?: string

# ? -> optional 
```

**Severity mapping (normalization):**
- Bandit: LOW → INFO, MEDIUM → WARNING, HIGH → ERROR
- Semgrep: map tool-specific severities into ERROR/WARNING/INFO

---

### ScanResult (Plugin Output Contract)

whole problem report generate by **Plugin**

```bash
- repo_url: string
- ref?: string                   # branch/tag/commit (user input)
- commit_sha?: string            # resolved SHA after checkout (if available)
- languages: string[]            # e.g. ["python", "javascript"]
- findings: Finding[]
- summary:
    - error_count: number
    - warning_count: number
    - info_count: number
- blocked: boolean               # true if policy blocks the workflow
- block_reason?: string          # present when blocked=true
```

## Interface Contracts

### RepoFetcher

**Purpose:** clone + checkout + manage temp workspace

- **Input**
  - `repo_url: string`
  - `ref?: string` (branch/tag/commit)
  - `auth: { token_env?: string }`
  - `limits: { clone_timeout_s: number, max_repo_size_mb?: number }`
- **Output**
  - `workspace: { path: string, commit_sha?: string }`
  - `cleanup(): void`
- **Failure modes**
  - clone/checkout fails → return error to plugin (plugin decides allow/block)

---

### LanguageDetector

**Purpose:** detect language(s) to select scanners

- **Input**
  - `repo_path: string`
- **Output**
  - `languages: string[]` (e.g. `["python"]`, `["javascript","typescript"]`)
- **Notes**
  - MVP heuristic: `pyproject.toml/requirements.txt/setup.py` → python; `package.json` → js/ts

---

### ScannerRunner (Generic Interface)

**Purpose:** run one scanner and return normalized findings (preferred)

- **Input**
  - `repo_path: string`
  - `scanner_config: object`
  - `timeout_s: number`
- **Output**
  - `findings: Finding[]`
  - (optional) `raw_output_ref?: string` (for debugging)
- **Implementations**
  - `SemgrepRunner`
  - `BanditRunner`

---

### Parser / Normalizer

**Purpose:** unify fields + merge + deduplicate

- **Input**
  - `findings_by_scanner: Finding[][]`
    - Raw: each scanner
    - Column: findings from each scanner
- **Output**
  - `merged_findings: Finding[]`
- **Dedup key (suggested MVP)**
  - `(scanner, rule_id, file_path, line, message)`

---

### Policy / Threshold Checker

**Purpose:** decide allow vs block

- **Input**
  - `findings: Finding[]`
  - `severity_threshold: "ERROR"|"WARNING"|"INFO"`
  - `fail_on_critical: boolean`
    - audit mode: only report no block -> false
    - enforce mode: block when reach threshold -> true
- **Output**
  - `decision: { blocked: boolean, reason?: string }`
- **Suggested rule (MVP)**
  - If `fail_on_critical=true` and any finding severity ≥ threshold → blocked=true

## Directory Structure

```bash
plugins/source_scanner/
  __init__.py                 # package init
  source_scanner.py           # Plugin + hooks + orchestration 
  config.py                   # Pydantic config models
  types.py                    # Finding / ScanResult unified schemas
  policy.py                   # threshold + block/allow decision
  errors.py                   # shared exception types (clone/scan/parse/timeout)
  repo_fetcher.py             # git clone/checkout + limits + cleanup (DevOps: Yasser)
  language_detector.py        # detect repo languages/ecosystem (2nd year #2)

  scanners/
    __init__.py
    semgrep_runner.py         # run semgrep + parse SARIF/JSON -> Finding[] (Ayo + 2nd #1)
    bandit_runner.py          # run bandit + parse JSON -> Finding[] (2nd #2)

  parsing/
    __init__.py
    normalizer.py             # merge + dedup + summary counts + severity normalize (2nd #3)

  storage/
    __init__.py
    models.py                 # DB models / tables for findings & scans (Arnav)
    repository.py             # save/load, cache by commit_sha, TTL (Arnav)

  utils/
    __init__.py
    exec.py                   # subprocess wrapper: timeout, stdout/stderr, rc

  tests/source_scanner/
    integration/
      test_scan_vulnerable_repo.py   # end-to-end: clone -> scan -> block/allow (Yasser)
    test_semgrep_runner.py           # runner-level tests (Ayo/Yasser)
    test_bandit_runner.py
    test_repo_fetcher.py
    test_language_detector.py
    test_normalizer.py
    test_policy.py

  plugin-manifest.yaml        # plugin registration metadata
  README.md                   # usage + config + dev notes (2nd #4 final)
```
