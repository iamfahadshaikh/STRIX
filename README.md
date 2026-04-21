# STRIX

STRIX is a precision-driven Vulnerability Assessment and Penetration Testing (VAPT) orchestration framework for authorized security testing.

It unifies reconnaissance, crawling, fingerprinting, validation, correlation, and reporting into one repeatable pipeline so teams can move from "raw scan noise" to "actionable, evidence-backed findings" faster.

> STRIX (Latin: strix) symbolizes sharp night vision. The framework follows that spirit: identify meaningful attack surface signals and verify findings with proof.

## Legal and ethical use first

STRIX must be used only on assets you own or are explicitly authorized to test.

- Allowed: internal infrastructure testing, approved client pentests, sanctioned bug bounty scope
- Not allowed: unauthorized scanning, intrusive testing outside scope, bypassing legal boundaries

Always keep signed authorization and scope boundaries documented before running scans.

## Table of contents

- [What problem STRIX solves](#what-problem-strix-solves)
- [Who should use STRIX](#who-should-use-strix)
- [Feature highlights](#feature-highlights)
- [High-level pipeline](#high-level-pipeline)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI usage examples](#cli-usage-examples)
- [Output structure and artifacts](#output-structure-and-artifacts)
- [Configuration and authentication](#configuration-and-authentication)
- [Methodology and confidence model](#methodology-and-confidence-model)
- [Operational guidance](#operational-guidance)
- [Troubleshooting](#troubleshooting)
- [Contributing and governance](#contributing-and-governance)

## What problem STRIX solves

Security testing workflows often break down because:

- Different tools output different formats and severity styles
- Teams manually stitch artifacts together, losing context
- Expensive tools run too early and produce unnecessary noise
- Findings are duplicated across scanners without correlation
- Reports lack validation evidence and confidence rationale

STRIX addresses this with an evidence-first orchestration model:

- Signal-driven execution gates
- Shared discovery context and caching
- Unified findings schema
- Deduplication + correlation layer
- Proof-oriented reporting with confidence scoring

## Who should use STRIX

STRIX is designed for:

- Pentesters running repeatable multi-tool assessments
- Security researchers validating web/API attack surface at scale
- DevSecOps teams integrating scans in CI/CD
- Internal red teams needing auditable assessment pipelines
- Security engineering teams that need consistent reports across projects

## Feature highlights

### 1) Smart execution gating

STRIX runs heavier or riskier modules only when prior discovery signals justify them.

Benefits:

- Reduces unnecessary requests
- Improves speed-to-signal
- Prevents blind brute-force style execution

### 2) Target-aware orchestration

STRIX classifies whether input is domain, subdomain, URL, or IP and adjusts execution strategy accordingly.

Benefits:

- Better defaults per target type
- Reduced misconfiguration risk
- Cleaner discovery coverage

### 3) Correlation and deduplication

Findings from multiple scanners are normalized and merged into single evidence-backed records.

Benefits:

- One issue, one finding (with multiple evidence points)
- Less triage overhead
- Better stakeholder readability

### 4) Proof-based reporting

STRIX favors findings with exploit/validation context over raw scanner alerts.

Benefits:

- Higher trust in reported issues
- Easier engineering handoff
- Better audit trails

### 5) Multi-format outputs

- JSON for machine processing and automation
- HTML for analyst and management review
- Text summaries for quick triage snapshots

## High-level pipeline

The default scan lifecycle:

```text
Input target
  -> Target normalization and classification
  -> Reachability and transport checks (HTTP/HTTPS)
  -> Decision ledger / execution gate planning
  -> Discovery and crawling
  -> Fingerprinting and enrichment
  -> Payload/validation modules (when allowed)
  -> Correlation + deduplication
  -> Confidence and risk scoring
  -> Report generation
```

### Pipeline intent markers

- [*] Discovery: maximize surface visibility
- [!] Validation: reduce false positives with proof
- [=] Correlation: join fragmented evidence into coherent findings
- [>] Reporting: publish deterministic artifacts for review

## Repository layout

Key workspace components:

- `strix.py`: CLI entry point
- `automation_scanner_v2.py`: orchestration runtime entry
- `requirements.txt`: Python dependencies
- `setup.py`: package/install metadata
- `config/`: authentication and runtime config files
- `docs/`: project-level documentation
- `src/`: primary engine modules and pipeline components
- `tests/`: automated testing suite
- `scan_results_*`: generated scan artifacts

Representative modules in `src/` include:

- Discovery and crawl orchestration (`api_discovery.py`, `crawl_adapter.py`, `crawler_integration.py`, `katana_crawler.py`, `light_crawler.py`)
- Decision and quality control (`decision_ledger.py`, `discovery_quality_scorer.py`, `discovery_metrics.py`, `discovery_completeness.py`)
- Findings processing (`finding_pipeline.py`, `finding_correlator.py`, `findings_model.py`, `deduplication_engine.py`)
- Confidence/risk systems (`confidence_engine.py`, `enhanced_confidence.py`, `global_confidence_system.py`)
- Reporting (`html_report_generator.py`, OWASP mapping modules)

## Requirements

### Runtime prerequisites

- Python 3.10+
- Windows, Linux, or WSL environment
- Stable network path to target systems
- Explicit test authorization and defined scope

### Typical external security tools

The exact set varies by profile and target, but common tools include:

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

Use STRIX tool checks before running production scans.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/strix.git
cd strix
```

### 2. Create and activate virtual environment

Create env:

```bash
python -m venv .venv
```

Activate on PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Activate on Linux/WSL:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

Development install:

```bash
pip install -r requirements.txt
```

Editable package install:

```bash
pip install -e .
```

### 4. Verify tool availability

If package-installed:

```bash
strix --check-tools
```

If running direct script:

```bash
python strix.py --check-tools
```

## Quick start

Minimal scan:

```bash
strix example.com
```

Script mode equivalent:

```bash
python strix.py example.com
```

Fast startup checklist ✅

1. Confirm target authorization and scope
2. Activate virtual environment
3. Run tool health check
4. Execute baseline scan
5. Review JSON + HTML outputs

## CLI usage examples

### Scan domain

```bash
strix example.com
```

### Scan full URL

```bash
strix https://example.com
```

### Use custom output directory

```bash
strix example.com -o ./my_results
```

### Install missing tools automatically

```bash
strix example.com --install-missing
```

### Interactive dependency install flow

```bash
strix example.com --install-interactive
```

### Pre-flight only (tool validation)

```bash
strix --check-tools
```

## Output structure and artifacts

Each execution generates a timestamped folder:

```text
scan_results_<target>_YYYYMMDD_HHMMSS/
```

Typical artifacts include:

- `execution_report.json`: normalized, machine-readable full report
- `security_report.html`: visual summary for analyst/stakeholder review
- `findings_summary.txt`: concise textual findings digest
- tool-specific raw artifacts (scanner outputs, crawl data, target lists)
- intermediate discovery data (endpoints, parameter candidates, reflections)

Example artifact classes from a typical run:

- Recon and network (`nmap_*`, `dnsrecon.txt`, `whatweb.txt`)
- Web crawl/discovery (`crawl_results.json`, endpoint/target files)
- Validation modules (`sqlmap.txt`, `dalfox.txt`, `xsstrike.txt`, `commix.txt`)
- TLS/security posture (`sslscan.txt`, `testssl.txt`, OpenSSL outputs)

## Configuration and authentication

### Config files

- `config/auth_config.example.json`: template for authenticated testing setup
- `config/auth_config.json`: local effective auth/session config

Recommended process:

1. Start from the example config
2. Add only scoped credentials/tokens
3. Keep secrets out of git history
4. Validate session behavior on a known-safe endpoint

### Authenticated scan caution

When authenticated modules are enabled:

- Use least-privilege test credentials
- Restrict scope to approved paths and hosts
- Avoid production-destructive payloads unless explicitly approved

## Methodology and confidence model

STRIX follows an evidence-weighted methodology:

1. Discover potential attack vectors
2. Enrich with context (tech fingerprint, parameter intelligence)
3. Attempt controlled validation
4. Score confidence based on corroborating evidence
5. Emit normalized findings with rationale

Confidence improves when multiple independent signals align, for example:

- crawler-discovered endpoint + scanner-positive signal
- reflection evidence + payload response markers
- duplicate issue class confirmed by separate tools

## Operational guidance

### Safe scanning defaults

- Begin with baseline discovery before heavy exploitation modules
- Tune scan pace on fragile environments
- Preserve full artifacts for later validation and reporting

### CI/CD integration mindset

Recommended CI stages:

1. Tool health check
2. Targeted baseline scan against staging
3. Parse JSON report and enforce gates
4. Publish HTML report as build artifact

### Performance and stability tips

- Keep third-party tools updated
- Run inside reproducible virtual environments
- Use WSL/Linux where shell-tool compatibility is stronger
- Separate reconnaissance and validation jobs for large scopes

## Troubleshooting

### Common issue: missing third-party binaries

Symptoms:

- tool not found errors
- empty or skipped module artifacts

Fix:

1. Run `strix --check-tools`
2. Install missing binaries in PATH
3. Re-run with a small target for sanity check

### Common issue: weak/empty findings on known-vulnerable target

Possible causes:

- crawler coverage too low
- blocked requests (WAF/rate limits)
- auth context not configured

Fix:

1. Verify discovery artifacts are populated
2. Confirm reachable endpoints and status codes
3. Re-run with authenticated scope if approved

### Common issue: report mismatch with raw tool data

Possible cause:

- deduplication/correlation collapsed duplicates into single normalized finding

Fix:

1. Cross-check `execution_report.json`
2. Inspect tool-specific raw artifacts in scan output folder
3. Review confidence and evidence sections before triage decisions

## Contributing and governance

Project governance files:

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
- `LICENSE`
- `CHANGELOG.md`

Please follow these documents when proposing improvements or reporting security issues.

## One-command memory jog

```bash
strix --check-tools && strix example.com
```

Happy hunting, responsibly.  [*] [!] [=] [>]

