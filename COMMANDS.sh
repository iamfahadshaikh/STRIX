#!/usr/bin/env bash
# VAPT Security Scanner - Quick Command Reference

cat << 'EOF'
╔════════════════════════════════════════════════════════════════════════════════╗
║         VAPT AUTOMATED SECURITY SCANNER - COMMAND REFERENCE                    ║
╚════════════════════════════════════════════════════════════════════════════════╝

📋 COMMON COMMANDS
═════════════════════════════════════════════════════════════════════════════════

1️⃣  CHECK TOOLS (before scanning)
    ──────────────────────────────────
    $ python3 automation_scanner_v2.py --check-tools

    ✓ Lists all 29 security tools
    ✓ Shows which are installed
    ✓ Prompts to install missing ones
    ✓ Installs selected tools

2️⃣  SCAN A TARGET
    ───────────────
    $ python3 automation_scanner_v2.py treadbinary.com
    $ python3 automation_scanner_v2.py https://example.com
    $ python3 automation_scanner_v2.py 192.168.1.1

    ✓ Automatic target type detection
    ✓ Comprehensive multi-phase scanning
    ✓ Saves results to scan_results_*/

3️⃣  SCAN WITH CUSTOM OUTPUT DIRECTORY
    ─────────────────────────────────────
    $ python3 automation_scanner_v2.py treadbinary.com -o ./my_results

4️⃣  AUTO-INSTALL MISSING TOOLS BEFORE SCANNING
    ──────────────────────────────────────────────
    $ python3 automation_scanner_v2.py treadbinary.com --install-missing

5️⃣  INTERACTIVE TOOL INSTALLATION
    ──────────────────────────────────
    $ python3 automation_scanner_v2.py treadbinary.com --install-interactive

═════════════════════════════════════════════════════════════════════════════════

📊 VIEW RESULTS
═══════════════════════════════════════════════════════════════════════════════

After scanning, view results in scan_results_<target>_<timestamp>/:

$ ls scan_results_treadbinary.com_*/
    execution_report.json   ← Detailed JSON report
    security_report.html    ← Visual HTML report
    crawl_results.json      ← Discovered endpoints
    *.txt                   ← Raw tool outputs

Open HTML report in browser:
$ firefox scan_results_treadbinary.com_*/security_report.html
$ chrome scan_results_treadbinary.com_*/security_report.html
$ xdg-open scan_results_treadbinary.com_*/security_report.html

═════════════════════════════════════════════════════════════════════════════════

🔍 CHECK SCAN PROGRESS
═══════════════════════════════════════════════════════════════════════════════

Monitor ongoing scans:
$ watch -n 5 'ls -lt scan_results_*/execution_report.json | head -1'

Or check in background:
$ tail -f scan_results_treadbinary.com_*/execution_report.json | grep -E 'tool|phase|complete'

═════════════════════════════════════════════════════════════════════════════════

🛠️ TROUBLESHOOTING
═════════════════════════════════════════════════════════════════════════════════

❌ "Tool not found" errors
   → Run: python3 automation_scanner_v2.py --check-tools
   → Select 'y' for each missing tool

❌ Permission denied (nmap, etc.)
   → Run with sudo: sudo python3 automation_scanner_v2.py <target>

❌ Scan is slow
   → Normal! Comprehensive scans take 5-30 minutes
   → Check progress: ls -lh scan_results_*/

❌ No results generated
   → Check execution_report.json for errors
   → Run with --check-tools to verify tool setup

═════════════════════════════════════════════════════════════════════════════════

📚 DOCUMENTATION
═════════════════════════════════════════════════════════════════════════════════

QUICKSTART_GUIDE.py              ← Full getting started guide
IMPLEMENTATION_COMPLETE_JAN13.md ← What was implemented
ARCHITECTURE.md                  ← Technical architecture
README.md                         ← Full documentation
HONEST_ROADMAP.md               ← Development roadmap

═════════════════════════════════════════════════════════════════════════════════

🚀 QUICK START (Recommended)
═════════════════════════════════════════════════════════════════════════════════

Step 1: Check and install tools
$ python3 automation_scanner_v2.py --check-tools

Step 2: Run your first scan
$ python3 automation_scanner_v2.py example.com

Step 3: View results
$ firefox scan_results_example.com_*/security_report.html

That's it! 🎉

═════════════════════════════════════════════════════════════════════════════════
EOF
