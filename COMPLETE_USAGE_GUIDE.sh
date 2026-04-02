#!/usr/bin/env bash

cat << 'EOF'

╔════════════════════════════════════════════════════════════════════════════════╗
║                    ✅ COMPLETE USAGE GUIDE                                     ║
║           VAPT Automated Security Scanner - All Flags & Options                ║
║                        January 13, 2026                                         ║
╚════════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════════
📋 MAIN COMMANDS
═══════════════════════════════════════════════════════════════════════════════════

1. CHECK & INSTALL TOOLS (No target required)
   ─────────────────────────────────────────────

   $ python3 automation_scanner_v2.py --check-tools

   • Lists all 29 security tools
   • Shows installation status (✅ or ❌)
   • No scanning - just tool verification
   • No target required
   ✓ BEST FOR: Verifying/installing tools before first scan

2. SCAN TARGET (Requires target)
   ───────────────────────────────

   $ python3 automation_scanner_v2.py treadbinary.com
   $ python3 automation_scanner_v2.py https://example.com
   $ python3 automation_scanner_v2.py 192.168.1.1

   • Runs full security assessment
   • 4 phases: Discovery → Crawler → Payloads → Report
   • Saves results to scan_results_<target>_<timestamp>/
   ✓ BEST FOR: Running security scans

3. SCAN WITH AUTO-INSTALL (Requires target)
   ──────────────────────────────────────────

   $ python3 automation_scanner_v2.py treadbinary.com --install-missing

   • Auto-installs any missing tools
   • Then scans the target
   • No prompts - fully automated
   ✓ BEST FOR: One-command security scan

4. SCAN WITH INTERACTIVE INSTALL (Requires target)
   ────────────────────────────────────────────────

   $ python3 automation_scanner_v2.py treadbinary.com --install-interactive

   • Shows all tools and installation status
   • Prompts: "Install <tool>? [y/n]"
   • Then scans the target
   ✓ BEST FOR: Selective tool installation before scanning

═══════════════════════════════════════════════════════════════════════════════════
⚙️  FLAG OPTIONS
═══════════════════════════════════════════════════════════════════════════════════

--check-tools
  Purpose: Check which tools are installed (no scanning)
  Usage:   python3 automation_scanner_v2.py --check-tools
  Target:  Optional (not used)
  Output:  Tool list with installation status

  Output example:
    ✅ nuclei - Fast vulnerability scanner [INSTALLED]
    ❌ arjun - HTTP parameter discovery [MISSING]
    SUMMARY: 28/29 tools installed, 1 missing

--install-missing
  Purpose: Auto-install all missing tools without prompts
  Usage:   python3 automation_scanner_v2.py [target] --install-missing
  Target:  Optional
  Behavior:
    • Without target: Install tools and exit
    • With target: Install tools, then scan target

  Examples:
    python3 automation_scanner_v2.py --install-missing
    python3 automation_scanner_v2.py example.com --install-missing

--install-interactive
  Purpose: Interactively choose which tools to install
  Usage:   python3 automation_scanner_v2.py [target] --install-interactive
  Target:  Optional
  Behavior:
    • Without target: Show tools, prompt for each, exit
    • With target: Show tools, prompt for each, then scan

  Prompts: "Install <tool>? [y/n/s]"
    y = yes, install this tool
    n = no, skip this tool
    s = skip all remaining tools

  Examples:
    python3 automation_scanner_v2.py --install-interactive
    python3 automation_scanner_v2.py example.com --install-interactive

--skip-install
  Purpose: Skip tool availability checks during scan
  Usage:   python3 automation_scanner_v2.py target --skip-install
  Effect:  Won't warn about missing tools (tools still required to run)

-o, --output <directory>
  Purpose: Specify output directory for results
  Usage:   python3 automation_scanner_v2.py target -o ./my_results
  Default: scan_results_<target>_<timestamp>/

═══════════════════════════════════════════════════════════════════════════════════
🎯 USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════════════

SCENARIO 1: First-time setup (tools not installed)
───────────────────────────────────────────────────
  $ python3 automation_scanner_v2.py --check-tools
  → Install tools interactively
  → Then run scan

SCENARIO 2: Quick scan with auto-install
──────────────────────────────────────────
  $ python3 automation_scanner_v2.py example.com --install-missing
  → Auto-installs missing tools
  → Runs full scan
  → Generates reports

SCENARIO 3: Selective tool installation
─────────────────────────────────────────
  $ python3 automation_scanner_v2.py example.com --install-interactive
  → Shows all tools
  → Prompts: Install nuclei? [y/n/s]: y
  →         Install sqlmap? [y/n/s]: n
  →         Install dalfox? [y/n/s]: y
  → etc...
  → Then runs scan

SCENARIO 4: Scan with custom output directory
──────────────────────────────────────────────
  $ python3 automation_scanner_v2.py example.com -o ./company_assessment
  → Results saved to ./company_assessment/

SCENARIO 5: Just check tools (no scanning)
────────────────────────────────────────────
  $ python3 automation_scanner_v2.py --check-tools
  → Lists all 29 tools
  → Shows installation status
  → Exits (no scanning)

SCENARIO 6: Full automated workflow
────────────────────────────────────
  $ python3 automation_scanner_v2.py example.com --install-missing
  $ firefox scan_results_example.com_*/security_report.html
  → One command to install tools and scan
  → View results in HTML browser

═══════════════════════════════════════════════════════════════════════════════════
📊 OUTPUT & RESULTS
═══════════════════════════════════════════════════════════════════════════════════

Scan results saved to: scan_results_<target>_<timestamp>/

Key files:
  execution_report.json  - Full technical report (machine-readable)
  security_report.html   - Visual security report (browser-friendly)
  crawl_results.json     - Discovered endpoints and parameters
  *.txt                  - Raw output from each tool (nmap, nuclei, etc)

View results:
  $ firefox scan_results_example.com_*/security_report.html
  $ cat scan_results_example.com_*/execution_report.json | jq

═══════════════════════════════════════════════════════════════════════════════════
🛠️ TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════════

Q: "Tool not found" error during scan?
A: Run: python3 automation_scanner_v2.py --check-tools
   Install missing tools when prompted

Q: Need to install specific tools?
A: Run: python3 automation_scanner_v2.py --install-interactive
   Say 'y' only for tools you want, 'n' for others

Q: Want to install all tools at once?
A: Run: python3 automation_scanner_v2.py --install-missing
   Then: python3 automation_scanner_v2.py <target>

Q: Permission denied during install?
A: Some tools need sudo. Try:
   sudo python3 automation_scanner_v2.py --install-missing

Q: How long does a scan take?
A: 5-30 minutes depending on target size and configuration
   Typical: 15-20 minutes for full assessment

═══════════════════════════════════════════════════════════════════════════════════
✅ QUICK START FLOW
═══════════════════════════════════════════════════════════════════════════════════

1. Check tools:
   $ python3 automation_scanner_v2.py --check-tools

2. Scan target:
   $ python3 automation_scanner_v2.py example.com

3. View results:
   $ firefox scan_results_example.com_*/security_report.html

═══════════════════════════════════════════════════════════════════════════════════
📚 DOCUMENTATION
═══════════════════════════════════════════════════════════════════════════════════

For more details:
  • README.md - Full documentation
  • ARCHITECTURE.md - Technical architecture
  • IMPLEMENTATION_COMPLETE_JAN13.md - What's implemented
  • QUICKSTART_GUIDE.py - Getting started guide

═══════════════════════════════════════════════════════════════════════════════════

EOF
