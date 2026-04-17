# VAPT Automated Engine

VAPT Automated Engine is a Python-based vulnerability assessment and penetration testing orchestration framework. It coordinates multiple reconnaissance, crawling, fingerprinting, exploitation-validation, and reporting components into a single workflow so security testing can be executed in a structured, repeatable, and evidence-driven way.

This project is designed for authorized security work only. Use it only on systems you own or have explicit permission to test.

## Why this project exists

Security testing often becomes slow and inconsistent because each tool produces different output formats, different confidence levels, and different assumptions about target scope. This engine was built to solve that problem by:

- Centralizing tool execution behind a single workflow
- Reducing noise by gating expensive steps on discovery signals
- Correlating results from multiple tools into normalized findings
- Producing consistent reports in JSON, HTML, and text formats
- Preserving evidence and confidence context instead of only raw tool output

In short, this project turns a loose collection of scanners into a production-style security testing pipeline.

## Who benefits from it

This project is useful for:

- Security researchers who want repeatable, automated recon and validation
- Penetration testers who need structured evidence and reports
- DevSecOps teams that want security checks in CI or scheduled pipelines
- Internal red teams that need a standardized target workflow
- Small security teams that want one orchestrator instead of many manual tools

## What it does

At a high level, the engine:

1. Classifies the target type, such as root domain, subdomain, or IP address
2. Probes reachability and HTTPS capability
3. Builds a decision ledger that controls which tools are allowed to run
4. Runs discovery, crawling, fingerprinting, and validation steps
5. Collects endpoints, parameters, reflections, and service signals
6. Correlates and deduplicates findings
7. Maps results to OWASP categories and confidence levels
8. Generates production-style reports

## Main capabilities

- Target classification for domains, subdomains, and IPs
- Decision-led tool orchestration instead of blind execution
- Discovery caching for endpoints, parameters, and reflections
- Crawler gating so payload tools only run when there is something to test
- Tool output parsing and normalization
- Findings deduplication and correlation
- Confidence scoring and severity alignment
- JSON, HTML, and summary report generation
- Runtime resilience with timeouts, retries, and fallback paths

## Core workflow

```text
Target input
  -> target classification
  -> HTTPS / reachability probe
  -> decision ledger
  -> discovery and crawl
  -> fingerprinting and enrichment
  -> payload validation where justified
  -> finding correlation and deduplication
  -> report generation
```

## Repository layout

The most important files and folders are:

- `automation_scanner_v2.py`: main orchestrator and entry point
- `decision_ledger.py`: tool allow/deny policy and execution routing
- `target_profile.py`: target classification model
- `cache_discovery.py`: discovery cache for endpoints, params, and reflections
- `crawler_integration.py`: crawler bridge and gating signals
- `crawler_mandatory_gate.py`: prevents payload tools from running too early
- `tool_manager.py`: tool availability checks and installation helpers
- `tool_parsers.py`: parser layer for external tool output
- `intelligence_layer.py`: correlation and confidence logic
- `findings_model.py`: normalized findings structures
- `risk_engine.py`: risk and severity scoring logic
- `html_report_generator.py`: HTML report output
- `proof_based_reporter.py`: confirmed-findings reporting
- `scan_results_*`: generated scan output folders, ignored by default
- `auth_config/`: authentication config for scoped testing
- `core/`, `modules/`, `auth_utils/`: auth and IDOR engine components
- `diagram/`: architecture or design assets
- `modules/`: reusable engine modules

## Requirements

### Runtime

- Python 3.10 or newer is recommended
- A Windows, Linux, or WSL environment
- Network access to the target when testing live systems
- Permission to test the target

### External tools

The scanner can coordinate many third-party utilities. The exact list depends on your environment and scan profile. Typical tools include:

- `nmap`
- `whatweb`
- `gobuster`
- `nikto`
- `sslscan`
- `testssl`
- `sqlmap`
- `nuclei`
- `xsstrike`
- `katana`

Use the built-in tool check before scanning so the engine can tell you what is installed and what is missing.

## Installation

### 1. Clone the repository

```bash
git clone <your-github-repo-url>
cd VAPT-Automated-Engine
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

On Linux or WSL:

```bash
source .venv/bin/activate
```

### 3. Install Python dependencies

This repository does not currently ship with a pinned `requirements.txt` or `pyproject.toml`. For a public release, add one before publishing so installation is reproducible.

Until then, install the Python packages your local environment needs for the scanner and its plugins, then verify imports by running the scanner's tool check.

### 4. Verify external tools

```bash
python automation_scanner_v2.py --check-tools
```

This will inspect which third-party binaries are available and which ones still need installation.

## Usage

### Basic scan

```bash
python automation_scanner_v2.py example.com
```

### Scan a full URL

```bash
python automation_scanner_v2.py https://example.com
```

### Scan with a custom output directory

```bash
python automation_scanner_v2.py example.com -o ./my_results
```

### Install missing tools before scanning

```bash
python automation_scanner_v2.py example.com --install-missing
```

### Interactive installation flow

```bash
python automation_scanner_v2.py example.com --install-interactive
```

## Output

Each scan creates a timestamped output directory such as:

```text
scan_results_example.com_YYYYMMDD_HHMMSS/
```

Typical outputs include:

- `execution_report.json`: structured machine-readable report
- `security_report.html`: human-readable dashboard
- crawler or discovery artifacts generated by the scan
- raw tool output files when enabled by the workflow

These folders are generated artifacts and should stay out of version control.

## How the reporting is organized

The engine is built around a few report layers:

- Discovery summary: endpoints, parameters, reflections, and surface signals
- Findings summary: normalized severity and OWASP counts
- Confirmed exploitation: proof-based findings after validation
- Phase and risk summaries: execution results and final risk view
- HTML report: presentation layer for quick review and sharing

## Configuration

Important configuration areas include:

- `auth_config/`: authentication and session settings for scoped testing
- `tool_manager.py`: tool mapping and installation metadata
- `scan_profiles.py`: scan behavior and profile tuning
- `decision_ledger.py`: execution policy and tool gating

Before running against authenticated or protected targets, configure the relevant auth files and validate that the scope is correct.

