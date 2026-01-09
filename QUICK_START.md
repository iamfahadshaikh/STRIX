# VAPT-Automated-Engine: Quick Start Guide

## Installation

```bash
cd VAPT-Automated-Engine

# Install dependencies
pip install -r requirements.txt

# (Optional) Update nuclei templates
nuclei -update-templates
```

## Basic Usage

### Single Target Scan
```bash
# HTTP subdomain
python3 automation_scanner_v2.py https://example.com --skip-install

# HTTPS root domain
python3 automation_scanner_v2.py https://example.com/

# IP address
python3 automation_scanner_v2.py https://192.168.1.1 --skip-install
```

### Output Files
```
scan_results_example.com_YYYYMMDD_HHMMSS/
├── execution_report.json          # Complete scan metadata + findings + intelligence
├── security_report.html           # Interactive dashboard (open in browser)
├── findings_summary.txt           # Human-readable summary
├── nmap_quick.txt                 # Discovered ports
├── nikto.txt                      # Web vulnerabilities
├── nuclei_crit.txt                # Nuclei critical findings
├── nuclei_high.txt                # Nuclei high findings
└── [other_tool_outputs].txt       # Individual tool output files
```

## Understanding the Reports

### security_report.html (📊 Interactive Dashboard)
- **Executive Summary:** Total findings, severity distribution, confidence metrics
- **Top 10 Critical Findings:** List with confidence meters and tool confirmation
- **Severity Distribution Chart:** Bar chart of CRITICAL/HIGH/MEDIUM/LOW findings
- **Compliance Mapping:** OWASP Top 10, CWE Top 25, PCI-DSS 3.2.1
- **Remediation Priority Queue:** Findings sorted by exploitability × confidence × attack surface

### execution_report.json (🔍 Machine-Readable)
```json
{
  "profile": { /* Target metadata */ },
  "execution": [ /* Tool execution results */ ],
  "findings": { /* Raw findings */ },
  "discoveries": { /* Discovered services, endpoints, subdomains */ },
  "intelligence": { /* Confidence scores, correlations, exploitability */ }
}
```

### findings_summary.txt (📝 Human-Friendly)
Lists findings above MEDIUM severity with OWASP mappings and deduplication.

---

## Key Features

### 1. **Adaptive Tool Orchestration**
Tools are gated based on discovered infrastructure:
- **Port discovery** (nmap) → gates nuclei execution
- **Web service confirmation** (nikto/whatweb) → gates gobuster
- **HTTPS service check** → gates sslscan

### 2. **Intelligent Finding Correlation**
- **Confidence scoring**: 0.0-1.0 based on tool reputation + multi-tool confirmation
- **Exploitability assessment**: CRITICAL/HIGH/MEDIUM/LOW based on vulnerability type
- **Attack surface quantification**: 0-10 score combining affected endpoints + auth status + public exposure
- **False positive filtering**: Removes test pages, CDN artifacts, WAF signatures

### 3. **Multi-Tool Finding Parsers**
Extracts normalized findings from:
- **nmap**: Open ports, outdated services
- **nikto**: OSVDB references, missing headers, tech stack
- **gobuster/dirsearch**: Sensitive paths (.git, .env, /admin)
- **xsstrike/xsser**: XSS vulnerabilities with payloads
- **sqlmap**: SQL injection with database enumeration
- **commix**: Command injection parameters
- **sslscan/testssl**: Weak protocols, weak ciphers, certificate issues

### 4. **Professional Reporting**
- **Interactive HTML** with responsive design and charts
- **Compliance mapping** to industry frameworks
- **Remediation guidance** by vulnerability type
- **Tool confirmation badges** showing multi-tool consensus

---

## Configuration

### Tool Timeouts
Edit `automation_scanner_v2.py` → `_run_tool()` to adjust timeouts:
```python
timeout = min(timeout, remaining)  # Default: tool-specific or 300s
```

### Tool Gating Rules
Edit `execution_paths.py` to modify prerequisites:
```python
("nuclei_crit", f"nuclei -u {url} -tags critical -silent",
 {"timeout": 9999, "category": "Nuclei", "prereqs": {"nmap_quick"}, "blocking": False})
```

### False Positive Filters
Edit `intelligence_layer.py` → `filter_false_positives()`:
```python
noise_patterns = {
    'test', 'demo', 'sample', 'staging',
    'cdn', 'cloudflare', 'akamai', 'dnsmasq'
}
```

---

## Troubleshooting

### Issue: "nuclei: no templates provided"
**Solution:** Install nuclei templates
```bash
nuclei -update-templates
```

### Issue: "nikto: connection refused"
**Solution:** Target may not have HTTP service on port 80
- Scanner will skip nikto if port not open
- Check nmap results: `cat scan_results_.../nmap_quick.txt`

### Issue: "HTTPS service not responding"
**Solution:** sslscan is skipped if HTTPS check fails
- Verify target has HTTPS service running
- Check firewall/WAF blocking HTTPS

### Issue: "No findings detected"
**Solution:** Target may be well-configured
- Check HTML report → Top 10 Critical section
- Look at findings_summary.txt for HIGH/MEDIUM severity
- Verify intelligence layer didn't filter all findings
- Check execution_report.json → discoveries section

---

## Performance Tips

### 1. Skip Install on Repeat Runs
```bash
python3 automation_scanner_v2.py https://example.com --skip-install
```
Saves ~30-60 seconds on tool verification.

### 2. Adjust Runtime Budget
Default is 900s (15 minutes). For faster scans:
```python
# In target_profile.py, adjust runtime_budget calculation
```

### 3. Monitor Tool Execution
Check logs in real-time:
```bash
tail -f scan_results_*/execution_report.json
```

---

## Output Interpretation

### Finding Severity Levels
- **CRITICAL**: RCE, SQL Injection, authentication bypass
- **HIGH**: Information disclosure, weak crypto, SSRF
- **MEDIUM**: Missing headers, outdated software, weak configuration
- **LOW**: Non-critical issues, informational findings
- **INFO**: Discovered services (no vulnerability)

### Confidence Scores
- **90%+**: Multiple tools confirmed same finding
- **70-90%**: Single reputable tool (nmap, sqlmap, nuclei)
- **50-70%**: Tool with lower reputation or pattern match
- **<50%**: Suspicious/low confidence, consider false positive

### Exploitability Ratings
- **CRITICAL**: Immediate exploitation possible
- **HIGH**: Exploitation requires moderate effort
- **MEDIUM**: Exploitation requires specific conditions
- **LOW**: Exploitation unlikely or requires social engineering

---

## Advanced Usage

### Custom Execution Plan
Modify `get_executor()` in `execution_paths.py` to add/remove tools for specific target types.

### Filter Results by Severity
```bash
python3 << 'EOF'
import json
with open('scan_results_*/execution_report.json') as f:
    findings = json.load(f)['findings']['findings']
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    print(f"Critical findings: {len(critical)}")
    for f in critical[:5]:
        print(f"  - {f['description'][:60]}")
EOF
```

### Extract All Findings to CSV
```bash
python3 << 'EOF'
import json
import csv
with open('scan_results_*/execution_report.json') as f:
    findings = json.load(f)['findings']['findings']
    
with open('findings.csv', 'w') as f:
    w = csv.writer(f)
    w.writerow(['Severity', 'Type', 'Location', 'Description', 'Tool', 'OWASP'])
    for finding in findings:
        w.writerow([
            finding['severity'],
            finding['type'],
            finding.get('location', ''),
            finding.get('description', '')[:60],
            finding.get('tool', ''),
            finding.get('owasp', '')
        ])
EOF
```

---

## Support & Debugging

### Verbose Logging
Scanner logs all tool execution to `[timestamp].log`:
```bash
tail -f latest_scan.log
```

### Check Tool Installation
```bash
# Verify all tools are available
python3 -c "from tool_manager import ToolManager; ToolManager().check_all()"
```

### Debug Single Tool
```bash
# Run nmap directly to verify output format
nmap -F testphp.vulnweb.com
```

---

## Security Notes

⚠️ **Disclaimer:** This tool performs active security testing. Only use on targets you have permission to scan.

- Tool execution is logged
- All findings are stored locally
- No data is sent to external services
- Results are JSON/HTML files - keep them secure

---

## Getting Help

1. Check `execution_report.json` → `execution` section for tool errors
2. Review tool output files (e.g., `nikto.txt`, `nmap_quick.txt`)
3. Check logs: `ls -t *.log | head -1 | xargs tail -50`
4. Verify target is reachable: `ping target.com`
5. Check tool availability: `which nmap nikto nuclei`

---

**Version:** 2.0 (Phase 2 Complete)  
**Last Updated:** January 8, 2026  
**Status:** Production Ready
