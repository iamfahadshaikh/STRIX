# Architecture-Driven VAPT Tool Orchestrator

**An intelligent security scanning engine that orchestrates 15-20 security tools with signal-driven gating, discovery caching, and findings intelligence.**

## What This Is

**Production-Ready Tool Orchestrator With Intelligence:**
- ✅ Architecture-driven tool routing (root domain vs subdomain vs IP)
- ✅ Signal-based gating (tools run only when prerequisites discovered)
- ✅ Discovery cache (findings from early tools gate later ones)
- ✅ Findings deduplication & correlation
- ✅ Intelligence layer (confidence scoring, cross-tool validation)
- ✅ Professional reporting (JSON, HTML, TXT with OWASP mapping)
- ✅ HTTPS capability probing & budget controls
- ✅ Structured outcomes (SKIPPED/BLOCKED/EXECUTED_NO_SIGNAL transparency)

**What This Is NOT:**
- ❌ A point-and-click GUI scanner
- ❌ A real-time vulnerability feed
- ❌ An automated remediation engine
- ❌ A compliance certification tool

**The Reality:**
This is a **professional pentesting automation framework** with:
- Intelligent orchestration (not just blind tool execution)
- Signal-driven decisions (not brute-force scanning)
- Normalized findings model (not raw tool dumps)
- Production-grade reporting (not just text files)

---

## Key Features

### Core Capabilities
- ✅ **~15-20 integrated tools** across DNS, Network, Web, SSL, Nuclei, and exploitation categories
- ✅ **Smart routing** - Different execution paths for root domains, subdomains, and IPs
- ✅ **Discovery-driven gating** - XSS tools only run if reflections found, SQLi only if params exist
- ✅ **Budget controls** - Runtime budgets, DNS time caps, timeout enforcement
- ✅ **HTTPS probe** - Explicit TLS handshake before SSL tool execution
- ✅ **Findings intelligence** - Correlation, confidence scoring, false positive filtering
- ✅ **Structured outcomes** - Clear SKIPPED/BLOCKED/SUCCESS semantics
- ✅ **Professional reporting** - JSON (source of truth), HTML (visual), TXT (findings summary)

---

## Installation

### Prerequisites

1. **Python 3.7+**
   ```bash
   python3 --version
   ```

2. **Required Python Packages**
   ```bash
   pip3 install tabulate
   ```

3. **Security Tools** (Install on Linux/Kali/WSL):
   ```bash
   # Automated installation via script
   python3 automation_scanner.py example.com --install-all

   # Or manual installation for Debian/Ubuntu/Kali
   sudo apt-get update
   sudo apt-get install -y \
       dnsutils dnsenum dnsrecon \
       nmap traceroute whois iputils-ping \
       openssl testssl.sh sslscan \
       wpscan whatweb xsser sqlmap

   # Python packages
   pip3 install \
       sslyze wpscan whatweb corsy \
       xsstrike dalfox xsser commix sqlmap \
       findomain sublister theharvester
   ```

## Quick Start

### Basic Usage

```bash
# Scan a domain (HTTPS probe determines protocol)
python3 automation_scanner_v2.py example.com

# Explicit HTTPS
python3 automation_scanner_v2.py https://example.com

# Explicit HTTP
python3 automation_scanner_v2.py http://example.com

# Custom output directory
python3 automation_scanner_v2.py example.com -o my_scan_results

# Skip tool installation checks
python3 automation_scanner_v2.py example.com --skip-install
```

### Target Types

```bash
# Root domain (broadest execution path)
python3 automation_scanner_v2.py google.com

# Subdomain (focused execution)
python3 automation_scanner_v2.py mail.google.com

# IP address (network-focused)
python3 automation_scanner_v2.py 142.251.32.46
```

## How It Works

### Architecture-Driven Execution Pipeline

**Stage 1: Target Classification**
- Parses target (URL, domain, or IP)
- Classifies type (root domain vs subdomain vs IP)
- Explicit HTTPS probe with cached verdict
- Builds immutable TargetProfile

**Stage 2: Decision Layer**
- Builds DecisionLedger based on target type
- Routes to appropriate executor (RootDomain/Subdomain/IP)
- Tool approval/denial based on capabilities

**Stage 3: Discovery Phase**
- DNS resolution, port scanning, web detection
- Results stored in DiscoveryCache
- Feeds forward to gate later tools

**Stage 4: Exploitation Phase (Gated)**
- XSS tools only if reflections found
- SQLi tools only if parameters discovered
- Command injection only if command-like params exist
- Budget enforcement prevents runaway scans

**Stage 5: Intelligence Processing**
- Tool output parsed into normalized Finding objects
- Findings deduplicated by hash
- Correlation identifies related findings
- Confidence scoring based on cross-tool agreement

**Stage 6: Professional Reporting**
- JSON: Complete execution metadata + findings
- HTML: Visual report with severity grouping
- TXT: OWASP-mapped findings summary
- All outputs include correlation ID for traceability

## Output Structure

```
scan_results_example.com_20260109_103022/
├── dig_a.txt                          # Individual tool outputs
├── nmap_quick.txt
├── whatweb.txt
├── nikto.txt
├── sslscan.txt
├── nuclei_crit.txt
│
├── execution_report.json              # Source of truth (outcomes, findings, discoveries, intelligence)
├── security_report.html               # Visual report with severity grouping
├── findings_summary.txt               # OWASP-mapped findings (CRITICAL/HIGH/MEDIUM)
│
└── [other tool outputs...]
```

## Report Examples

### Executive Summary
```
TARGET: example.com
RISK SCORE: 82/100
SEVERITY: CRITICAL - IMMEDIATE ACTION REQUIRED

TOP FINDINGS:
1. Certificate Expired (CVSS: 7.5)
   → Renew certificate from CA immediately

2. Weak TLS Ciphers (CVSS: 6.5)
   → Configure server to use only strong ciphers

3. SQL Injection Vulnerability (CVSS: 9.8)
   → Implement parameterized queries
```

### Vulnerability Report (JSON)
```json
{
  "target": "example.com",
  "risk_score": 82,
  "vulnerabilities": [
    {
      "type": "Expired Certificate",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "description": "SSL certificate has expired",
      "remediation": "Renew certificate from CA",
      "cve": "N/A"
    }
  ]
}
```

## Understanding CVSS Scores

The tool calculates CVSS 3.1 scores automatically:

- **9.0-10.0 (Critical)**: Immediate remediation required
- **7.0-8.9 (High)**: Urgent remediation needed
- **4.0-6.9 (Medium)**: Plan remediation
- **0.1-3.9 (Low)**: Monitor and plan
- **0.0 (Info)**: Informational

## Custom Risk Score (0-100)

- **≥75**: 🔴 CRITICAL - Fix immediately
- **50-74**: 🟠 HIGH - Urgent action needed
- **25-49**: 🟡 MEDIUM - Plan remediation
- **<25**: 🟢 LOW - Monitor

## Supported Tools

### DNS & Subdomain Enumeration
- assetfinder, dnsrecon, host, dig, nslookup, dnsenum
- findomain, sublister, theharvester

### Network Scanning
- nmap, ping, traceroute, whois

### SSL/TLS Analysis
- testssl.sh, sslyze, sslscan, openssl

### Web Application
- whatweb, wpscan, corsy

### Vulnerability Detection
- xsstrike, dalfox, xsser, commix, sqlmap

## Troubleshooting

### "Tool not found"
The scanner automatically skips unavailable tools and continues. To install:
```bash
python3 automation_scanner.py example.com --install-all
```

### Permission Denied
Some tools require elevated privileges:
```bash
sudo python3 automation_scanner.py example.com
```

### Timeout Issues
Increase timeout in code or add --timeout parameter if available

### Missing Tabulate Package
```bash
pip3 install tabulate
```

## Comparing to Burp Suite / OWASP ZAP

| Feature | This Tool | Burp Suite | OWASP ZAP |
|---------|-----------|-----------|-----------|
| Automated Reconnaissance | ✅ | ⚠️ Limited | ⚠️ Limited |
| Multi-Tool Integration | ✅ | ❌ | ❌ |
| CVSS Scoring | ✅ Auto | ⚠️ Manual | ⚠️ Manual |
| DNS Enumeration | ✅ | ❌ | ❌ |
| Subdomain Discovery | ✅ | ❌ | ❌ |
| Remediation Guidance | ✅ Detailed | ⚠️ Basic | ⚠️ Basic |
| Risk Scoring (0-100) | ✅ | ❌ | ❌ |
| Cost | ✅ Free | ❌ Paid | ✅ Free |
| Batch Processing | ✅ | ❌ | ❌ |

## Performance Tips

1. **Use specific categories** instead of full scan:
   ```bash
   # Only DNS (if you create category-specific commands)
   python3 automation_scanner.py example.com --dns-only
   ```

2. **Run during off-peak hours** to avoid overloading target

3. **Increase delays** between tools if needed:
   - Edit `automation_scanner.py` and modify `time.sleep(0.5)`

4. **Use HTTP only** for faster preliminary scans:
   ```bash
   python3 automation_scanner.py example.com -p http
   ```

## Legal & Ethical Considerations

⚠️ **IMPORTANT**: Only scan systems you own or have written authorization to test.

- Obtain explicit written permission before scanning
- Use responsibly and ethically
- Respect rate limits and server resources
- Comply with all applicable laws and regulations
- Never use on production systems without permission

## Platform Support

- ✅ Linux (Kali, Ubuntu, Debian, etc.)
- ✅ WSL (Windows Subsystem for Linux)
- ✅ macOS (with tool installations)
- ❌ Native Windows (use WSL recommended)

## File Descriptions

### automation_scanner.py
Main automation engine with all scanning logic

### tool_manager.py
Detects, lists, and installs security tools

### vulnerability_analyzer.py
Parses outputs and calculates CVSS scores

### scanner_config.py
Configuration file for customization

## Advanced Customization

### Add New Tool
1. Add to `tool_database` in `tool_manager.py`
2. Create scan method in `automation_scanner.py`
3. Add analysis patterns in `vulnerability_analyzer.py`

### Modify CVSS Scoring
Edit `CVSSCalculator.calculate_score()` in `vulnerability_analyzer.py`

### Change Risk Thresholds
Modify `calculate_overall_risk_score()` in `vulnerability_analyzer.py`

## Example Output

```
[10:15:23] [INFO] Output directory: scan_results_example.com_20240116_101523
[10:15:23] [INFO] Correlation ID: 20240116_101523
[10:15:23] [INFO] Protocol: both

[10:15:24] [SECTION] Starting DNS Reconnaissance
[10:15:25] [RUN] Running assetfinder...
[10:15:30] [SUCCESS] assetfinder completed successfully
[10:15:31] [RUN] Running dnsrecon_std...
[10:15:38] [SUCCESS] dnsrecon_std completed successfully
...

================================================================================
TOOL EXECUTION RESULTS SUMMARY
================================================================================
┌──────────────────────────┬──────────────┬─────────────────┬──────────────────┐
│ Tool Name                │ Status       │ Execution Time  │ Output Size      │
├──────────────────────────┼──────────────┼─────────────────┼──────────────────┤
│ assetfinder              │ ✓ SUCCESS    │ 10:15:29        │ 1024             │
│ dnsrecon_std             │ ✓ SUCCESS    │ 10:15:37        │ 2048             │
│ nmap_fast                │ ✓ SUCCESS    │ 10:16:45        │ 512              │
│ testssl_full             │ ✓ SUCCESS    │ 10:17:12        │ 8192             │
└──────────────────────────┴──────────────┴─────────────────┴──────────────────┘

Total Tools Run: 25
Successful: 24
Failed: 1

[10:20:45] [INFO] Scan completed in 305.23 seconds
[10:20:45] [INFO] Results saved to: scan_results_example.com_20240116_101523
```

---

## The Next Phase: Building Intelligence

If you want to turn this orchestrator into a **real scanner**, you need:

### Phase 2: Parser Layer (Recommended Next Step)

```python
# New module: finding_parser.py
# Converts tool outputs → standardized findings

class FindingParser:
    def parse_xsstrike_output(self, stdout) -> List[Finding]:
        # Extract XSS findings from xsstrike JSON
        # Return canonical Finding objects

    def parse_sqlmap_output(self, stdout) -> List[Finding]:
        # Extract SQLi findings

    # ... parsers for all 32 tools

class Finding:
    tool: str              # "xsstrike"
    type: str              # "xss"
    url: str               # "https://site.com/search"
    parameter: str         # "q"
    payload: str           # "The actual payload"
    confidence: float      # 0.0-1.0 (how sure?)
    severity: str          # "critical"
    cvss: float            # CVSS score
    evidence: str          # Raw proof from tool
```

### Phase 2B: Deduplication

```python
# New module: deduplication.py

class Deduplicator:
    def dedupe_findings(self, findings: List[Finding]) -> List[Finding]:
        # xsstrike + dalfox both find XSS on /search?q
        # Return 1 finding with both tools listed

        # Result:
        # - /search?q has 1 XSS (confirmed by 2 tools)
        # - Confidence: 0.95
        # - Not 2 separate findings
```

### Phase 2C: Risk Engine

```python
# New module: risk_engine.py

class RiskCalculator:
    def calculate_risk(self, findings: List[Finding]) -> RiskScore:
        # Weight by: severity, exploitability, exposure
        # Not just CVSS

        # Example scoring:
        # - Exposed admin panel (unauthenticated) = HIGH RISK
        # - Requires authenticated user = LOWER RISK
        # - API-only (not web-facing) = LOWER RISK
```

### Phase 3: Decision Engine

```python
# New module: gate_engine.py

class GateDecision:
    def should_deploy(self, risk_score: RiskScore) -> bool:
        # If critical + exploitable + unauthenticated = FAIL
        # If high + requires admin access = WARN
        # If low + can patch in 24h = PASS

        return risk_score < self.deployment_threshold
```

This approach:
- ✅ Keeps your orchestrator as-is (it's working)
- ✅ Adds parsing layer on top
- ✅ Maintains loose coupling
- ✅ Makes findings deduplicated + prioritized
- ✅ Enables actual gate decisions

---

## Contributing

To improve or extend the tool:

1. Test changes thoroughly
2. Update documentation
3. Add new tool functions following the pattern
4. Consider: Are you adding execution coverage or parsing intelligence?

## Support & Issues

If you encounter issues:

1. Check tool outputs in the scan results directory
2. Review `EXECUTIVE_SUMMARY.txt` for execution status
3. Verify tool installations with `tool_manager.py`
4. Remember: If a tool fails, check its dependencies (this is an orchestrator, not a solver)

---

**Last Updated**: January 2026
**Version**: 3.0 (Tool Orchestrator Edition)
**Honest Assessment**: Phase 1 Complete (Execution), Phase 2 Needed (Intelligence)
**License**: Use responsibly on authorized systems only

---

### The Truth in One Sentence

> **This is an excellent Python framework for running many external pentesting tools and collecting their outputs. It's not yet a vulnerability scanner or deployment gate, but it's the hard infrastructure that such systems need to be built on top of.**
