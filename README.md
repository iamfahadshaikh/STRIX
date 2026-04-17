# STRIX

**STRIX** is a precision-driven vulnerability assessment and penetration testing orchestration framework. It coordinates multiple reconnaissance, crawling, fingerprinting, exploitation-validation, and reporting components into a single workflow so security testing can be executed in a structured, repeatable, and evidence-driven way.

STRIX is designed for authorized security work only. Use it only on systems you own or have explicit permission to test.

> **STRIX**: From Latin *strix*, the Roman owl of night and prophecy. An intelligent reconnaissance system that sees what others miss.

## Why STRIX exists

Security testing often becomes slow and inconsistent because each tool produces different output formats, different confidence levels, and different assumptions about target scope. STRIX solves this by:

- Centralizing tool execution behind a single workflow
- Reducing noise by gating expensive steps on discovery signals
- Correlating results from multiple tools into normalized findings
- Producing consistent reports in JSON, HTML, and text formats
- Preserving evidence and confidence context instead of only raw tool output

In short, STRIX orchestrates multiple scanners into a unified, evidence-driven security testing pipeline.

## Who uses STRIX

STRIX is built for:

- Security researchers who need repeatable, automated recon and validation
- Penetration testers who require structured evidence and OWASP-mapped reports
- DevSecOps teams that want security checks in CI/CD pipelines
- Internal red teams that need standardized, auditable scan workflows
- Security teams that want single-pane-of-glass orchestration

## What STRIX does

At a high level, STRIX:

1. Classifies the target type, such as root domain, subdomain, or IP address
2. Probes reachability and HTTPS capability
3. Builds a decision ledger that controls which tools are allowed to run
4. Runs discovery, crawling, fingerprinting, and validation steps
5. Collects endpoints, parameters, reflections, and service signals
6. Correlates and deduplicates findings
7. Maps results to OWASP categories and confidence levels
8. Generates production-style reports

## STRIX capabilities

- **Intelligent gating**: Tools execute only when discovery signals justify them
- **Target classification**: Domains, subdomains, IP addresses with context-aware scanning
- **Evidence caching**: Endpoints, parameters, reflections stored and correlated
- **Tool orchestration**: Coordinates 15+ security tools with unified output parsing
- **Proof-based reporting**: Confirmed findings only; confidence scores for each result
- **Deduplication & correlation**: Same vulnerability from multiple tools = one finding
- **OWASP mapping**: Automatic severity and category alignment
- **Multi-format reports**: JSON (machine), HTML (visual), text (summary)
- **Resilience**: Timeouts, retries, fallbacks, state recovery

## STRIX workflow

```text
Target
  ↓
  Target Classification (domain/subdomain/IP)
  ↓
  HTTPS & Reachability Probe
  ↓
  Decision Ledger (which tools are authorized)
  ↓
  Discovery & Crawling
  ↓
  Fingerprinting & Enrichment
  ↓
  Payload Validation (with proof requirements)
  ↓
  Correlation & Deduplication
  ↓
  Report Generation
```

## STRIX architecture

Core entry and implementation files:

- `strix.py`: main entry point (use this to run STRIX)
- `automation_scanner_v2.py`: core orchestration engine
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

### 1. Clone STRIX

```bash
git clone https://github.com/yourusername/strix.git
cd strix
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

**Option A: Direct installation (development)**

```bash
pip install -r requirements.txt
```

**Option B: Install as a package (recommended)**

```bash
pip install -e .
```

This installs STRIX as a package with the `strix` command available globally.

External security tools (nmap, nuclei, etc.) must be installed separately.

### 4. Verify external tools

**If installed via pip:**

```bash
strix --check-tools
```

**If running directly:**

```bash
python strix.py --check-tools
```

This will inspect which third-party binaries are available and which ones still need installation.

## Usage

### Basic scan

```bash
strix example.com
```

Or if not installed via pip:

```bash
python strix.py example.com
```

### Scan a full URL

```bash
strix https://example.com
```

### Scan with a custom output directory

```bash
strix example.com -o ./my_results
```

### Install missing tools before scanning

```bash
strix example.com --install-missing
```

### Interactive tool installation

```bash
strix example.com --install-interactive
```

## STRIX output

Each scan creates a timestamped output directory:

```text
scan_results_example.com_YYYYMMDD_HHMMSS/
```

Typical outputs include:

- `execution_report.json`: structured machine-readable report
- `security_report.html`: human-readable dashboard
- crawler or discovery artifacts generated by the scan
- raw tool output files when enabled by the workflow

These folders are generated artifacts and should stay out of version control.

## STRIX reports

STRIX generates multi-layer reports:

- Discovery summary: endpoints, parameters, reflections, and surface signals
- Findings summary: normalized severity and OWASP counts
- Confirmed exploitation: proof-based findings after validation
- Phase and risk summaries: execution results and final risk view
- HTML report: presentation layer for quick review and sharing

## STRIX configuration

Key config areas:

- `auth_config/`: authentication and session settings for scoped testing
- `tool_manager.py`: tool mapping and installation metadata
- `scan_profiles.py`: scan behavior and profile tuning
- `decision_ledger.py`: execution policy and tool gating

Before testing authenticated or protected targets, configure STRIX's auth settings and verify scope.

## Quick install and run

For the impatient:

```bash
git clone https://github.com/yourusername/strix.git
cd strix
pip install -e .
strix --check-tools
strix example.com
```

Done. STRIX handles the rest.

