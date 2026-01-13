#!/usr/bin/env python3
"""
QUICK START GUIDE - VAPT Automated Security Scanner

This guide helps you run the security scanner with all necessary tools properly installed.
"""

print("""
╔════════════════════════════════════════════════════════════════════════════════╗
║                  VAPT AUTOMATED SECURITY SCANNER - QUICK START                 ║
╚════════════════════════════════════════════════════════════════════════════════╝

📋 OVERVIEW:
   This is an Architecture-Driven Vulnerability Assessment and Penetration Testing
   (VAPT) framework that performs comprehensive security scans on web targets.

═══════════════════════════════════════════════════════════════════════════════════

🛠️  STEP 1: CHECK AND INSTALL TOOLS
   ────────────────────────────────────

   Before running scans, check which security tools are installed and install missing ones:

   $ python3 automation_scanner_v2.py --check-tools

   This command will:
   ✓ List all 29 security tools used by the scanner
   ✓ Show which tools are installed on your system
   ✓ Prompt you for each missing tool (yes/no)
   ✓ Install selected tools automatically

   Tools include: nmap, nuclei, dalfox, sqlmap, xsstrike, gobuster, dirsearch,
                 nikto, whatweb, testssl, sslscan, sublist3r, findomain, and more.

═══════════════════════════════════════════════════════════════════════════════════

🚀 STEP 2: RUN A SECURITY SCAN
   ─────────────────────────────

   After tools are installed, run a scan on your target:

   $ python3 automation_scanner_v2.py <target-url>

   Examples:
   $ python3 automation_scanner_v2.py treadbinary.com
   $ python3 automation_scanner_v2.py https://example.com
   $ python3 automation_scanner_v2.py 192.168.1.1

   The scanner will:
   ✓ Auto-detect the target type (domain, subdomain, IP)
   ✓ Run Phase 1: Discovery (DNS, SSL/TLS, external intel)
   ✓ Run Phase 2: Mandatory Crawler (discover endpoints/params)
   ✓ Run Phase 3: Payload Testing (XSS, SQLi, RCE scanning)
   ✓ Run Phase 4: Report Generation (HTML + JSON)
   ✓ Save results to: scan_results_<target>_<timestamp>/

═══════════════════════════════════════════════════════════════════════════════════

📊 STEP 3: VIEW RESULTS
   ────────────────────

   After the scan completes, results are saved in:
   scan_results_<target>_<timestamp>/

   Key files:
   • execution_report.json  - Full technical report (JSON)
   • security_report.html   - Visual security report (HTML)
   • crawl_results.json     - Endpoints/parameters discovered
   • *.txt                  - Raw tool outputs (nmap, nuclei, etc.)

   Open the HTML report in a browser:
   $ xdg-open scan_results_*/security_report.html

═══════════════════════════════════════════════════════════════════════════════════

⚙️  OPTIONS AND FLAGS
   ──────────────────

   --check-tools              List all tools and prompt to install missing ones
   -o/--output <dir>          Specify output directory (default: auto-generated)
   --skip-tool-check          Skip tool availability checks
   --install-missing          Auto-install missing tools (non-interactive)
   --install-interactive      Prompt for each missing tool during installation

   Examples:
   $ python3 automation_scanner_v2.py treadbinary.com -o ./my_results
   $ python3 automation_scanner_v2.py treadbinary.com --install-missing

═══════════════════════════════════════════════════════════════════════════════════

🎯 WHAT THE SCANNER DOES
   ────────────────────────

   PHASE 1: DISCOVERY
   ├─ DNS Enumeration (dnsrecon, dig, assetfinder, findomain, sublist3r)
   ├─ Web Technology Fingerprinting (whatweb)
   ├─ SSL/TLS Analysis (testssl, sslscan)
   ├─ External Intelligence (crt.sh certificates)
   └─ Network Scanning (nmap)

   PHASE 2: MANDATORY CRAWLER
   ├─ Endpoint Discovery (Katana crawler)
   ├─ Parameter Extraction
   ├─ Reflection Detection (XSS vectors)
   └─ Gating Decision (payload tools readiness)

   PHASE 3: PAYLOAD TESTING (if crawler succeeds)
   ├─ Cross-Site Scripting (dalfox, xsstrike)
   ├─ SQL Injection (sqlmap)
   ├─ Command Injection (commix)
   ├─ Template Scanning (nuclei with custom templates)
   └─ Parameter Discovery (arjun, gobuster, dirsearch)

   PHASE 4: REPORTING
   ├─ Vulnerability Summary (by type and severity)
   ├─ Risk Aggregation (business impact)
   ├─ Coverage Analysis (what was tested)
   ├─ Findings Deduplication (remove duplicates)
   └─ HTML + JSON Export

═══════════════════════════════════════════════════════════════════════════════════

📈 TOOL COVERAGE
   ──────────────

   29 Security Tools Integrated:
   
   DNS (6):
     assetfinder, dnsrecon, dig, dnsenum, host, nslookup

   Network (4):
     nmap, ping, traceroute, whois

   SSL/TLS (4):
     testssl, sslscan, openssl, sslyze

   Web (5):
     whatweb, gobuster, dirsearch, nikto, wpscan

   Vulnerabilities (7):
     xsstrike, dalfox, xsser, sqlmap, commix, nuclei, arjun

   Subdomains (3):
     findomain, sublist3r, theharvester

═══════════════════════════════════════════════════════════════════════════════════

🔧 TROUBLESHOOTING
   ────────────────

   Q: A tool is not installed?
   A: Run `python3 automation_scanner_v2.py --check-tools` and select "y" for each tool

   Q: Scan is too slow?
   A: This is normal for comprehensive scans. They typically take 5-30 minutes.

   Q: No vulnerabilities found?
   A: This could mean:
      - Discovery was incomplete (check Phase 1c completeness score)
      - Target is secure (good news!)
      - Tools need updating

   Q: Permission denied errors?
   A: Some tools like nmap need elevated privileges:
      $ sudo python3 automation_scanner_v2.py <target>

═══════════════════════════════════════════════════════════════════════════════════

📞 SUPPORT
   ────────

   For issues or improvements, check:
   • ARCHITECTURE.md  - Architecture overview
   • README.md        - Full documentation
   • HONEST_ROADMAP.md - Development roadmap

═══════════════════════════════════════════════════════════════════════════════════
""")
