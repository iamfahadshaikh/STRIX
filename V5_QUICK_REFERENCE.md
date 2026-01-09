# v5 Quick Reference Card

## Decision Layer Rules (Remember These!)

### When does a tool run?

```
1. BLOCK if:
   - Required capability missing (e.g., web_target for nuclei)
   - Tool not in allowed list (policy denied)
   → Tool does NOT execute
   → Outcome: EXECUTION_ERROR

2. SKIP if:
   - Runtime budget insufficient for worst-case
   - All produces already present (redundant)
   - DNS budget exhausted
   → Tool does NOT execute
   → Outcome: SUCCESS_NO_FINDINGS (for stats)

3. ALLOW (execute) if:
   - All required capabilities present
   - Runtime budget sufficient
   - Might produce new signal
   ← Optional capabilities missing? Still ALLOW (reduced confidence)
```

---

## Signal Classification (What Do Tool Outputs Mean?)

```
POSITIVE: Found actionable data
  ├─ nmap: " open " in stdout
  ├─ whatweb: recognized tech (Apache, PHP, WordPress)
  ├─ gobuster: "Status:200" endpoint
  └─ nikto: vulnerability found

NO_SIGNAL: Ran OK, found nothing useful
  ├─ whatweb: no recognized tech
  ├─ nmap: all ports closed
  ├─ gobuster: no directories found
  └─ Any tool: empty stdout

NEGATIVE_SIGNAL: Confirmed absence (blocks downstream)
  ├─ nmap: definitely no ports open
  ├─ dns: definitely no A records
  └─ Used sparingly (most tools produce NO_SIGNAL, not NEGATIVE)
```

---

## Discovery Cache: What Triggers What?

```
Tool Output              → Cache Update        → Planning Impact
════════════════════════════════════════════════════════════════

gobuster finds /admin    → add_live_endpoint() → commix/dalfox can run
                            (HTTP 200)         

nmap finds port 8080     → add_port()          → web enum can target
                                                 that port

whatweb finds WordPress  → tech_stack_detected → custom WordPress
                                                 exploits enabled

Parameter "id" found     → add_param()         → injection tools gate
                            (auto-detects type: 
                             cmd, ssrf, xss)   

XSS reflection test +    → add_reflection()    → dalfox unblocks
```

---

## Nuclei: The New Flow

```
OLD: whatweb → nuclei blocked if no tech stack found
     (Bad: whatweb findings not actionable for nuclei)

NEW: nuclei only needs web_target
     whatweb findings are OPTIONAL, not required
     Nuclei runs on ANY web URL regardless

Configuration:
  requires: {web_target}           ← HARD requirement
  optional: {live_endpoints, ...}  ← Nice to have
  
Decision logic:
  if not web_target:
    BLOCK (can't run nuclei on non-web)
  else:
    ALLOW (nuclei runs)
```

---

## DNS Consolidation (Root vs Subdomain)

```
ROOT DOMAIN (e.g., example.com):
  ├─ Tool: dnsrecon (one call, all record types)
  ├─ Time: ~6 seconds
  └─ Produces: A, NS, MX, TXT, SOA records
     
SUBDOMAIN (e.g., api.example.com):
  ├─ Tool: dig_a (verify A record exists)
  ├─ Tool: dig_aaaa (verify IPv6 exists)
  ├─ Time: ~2 seconds total
  └─ Purpose: Quick verification, not enumeration

WHY?
  Root needs full recon (authority discovery, mail servers)
  Subdomain just needs "is it resolvable?" (yes/no)
```

---

## _run_tool() Workflow (Internals)

```python
_run_tool(plan_item)
├─ 1. Check decision:
│    decision, reason = _should_run(tool, plan_item)
│    if BLOCK or SKIP: return early
│
├─ 2. Execute subprocess:
│    stdout, stderr, rc = _execute_tool_subprocess(cmd, timeout)
│
├─ 3. Classify outcome:
│    outcome, status = _classify_execution_outcome(tool, rc, ...)
│    Handles: rc=0 (SUCCESS), rc=141 (PARTIAL/SIGPIPE), rc=X (ERROR)
│
├─ 4. Filter output:
│    filtered = _filter_actionable_stdout(tool, stdout)
│    Removes noise, extracts signal
│
├─ 5. Extract findings:
│    _extract_and_cache_findings(tool, filtered, stderr)
│    Parses findings, populates cache, updates context
│
└─ 6. Return result:
    {tool, status, outcome, reason, ...}
```

---

## Common Gotchas (Don't Do These!)

❌ Don't assume whatweb finds tech → nuclei can run
   ✅ Check web_target capability instead

❌ Don't treat rc=141 as error (it's SIGPIPE)
   ✅ rc=141 + stdout = partial success

❌ Don't run 5 DNS tools on root domain
   ✅ Use dnsrecon (one tool, all records)

❌ Don't manually add to live_endpoints using endpoints.add()
   ✅ Use cache.add_live_endpoint() method

❌ Don't mix BLOCK/SKIP/SKIPPED/DENIED terminology
   ✅ Use DecisionOutcome enum values

---

## Adding a New Tool: Checklist

```
1. Add to execution_paths.py:
   (tool_name, command, {"requires": {...}, "optional": {...}, ...})
   
2. If tool outputs findings:
   Add parsing to tool_parsers.py
   
3. Add signal extraction:
   Tool-specific filters in _filter_actionable_stdout()
   
4. Update cache if needed:
   e.g., if tool finds ports: cache.add_port()
   
5. Test:
   Run scanner on test target
   Verify tool executes with ALLOW (not BLOCK)
   Check findings in output
   
6. Document:
   Add tool to relevant phase (DNS, Web, Vuln, etc.)
```

---

## Execution Flow Overview

```
USER INPUT
   │
   ├─ Target: "https://example.com"
   │  (User input is authoritative: scheme, host, port)
   │
TARGET PROFILE
   │
   ├─ Type: ROOT_DOMAIN / SUBDOMAIN / IP_ADDRESS
   │ Schema: https, host: example.com, port: 443, is_web: True
   │
EXECUTOR PATH (RootDomainExecutor, SubdomainExecutor, IPAddressExecutor)
   │
   ├─ Build execution plan (list of tools)
   │
DECISION LEDGER
   │
   ├─ Filter allowed tools (by policy)
   │
FOR EACH TOOL IN PLAN:
   │
   ├─ Decision: _should_run(tool)
   │  ├─ Check requires: BLOCK if missing
   │  ├─ Check budget: SKIP if over
   │  ├─ Check redundancy: SKIP if already have
   │
   ├─ Execution: _execute_tool_subprocess()
   │  ├─ Run command
   │  ├─ Capture stdout/stderr/rc
   │
   ├─ Classification: _classify_execution_outcome()
   │  ├─ Map rc → ToolOutcome
   │  ├─ Special cases (rc=141, etc.)
   │
   ├─ Filtering: _filter_actionable_stdout()
   │  ├─ Remove noise
   │  ├─ Extract signal
   │
   ├─ Extraction: _extract_and_cache_findings()
   │  ├─ Parse findings
   │  ├─ Populate cache
   │  ├─ Update context
   │
   ├─ Planning Context Updated:
   │  ├─ ports_known, endpoints_known, live_endpoints, etc.
   │
   └─ Next tool sees updated context
         │
         (Loop continues)
         │
RESULTS
   │
   ├─ Findings Registry (deduplicated, correlated)
   ├─ Discovery Summary (what was found)
   ├─ Execution Log (who ran, why, outcome)
   └─ Intelligence (confidence scores)
```

---

## Performance Targets (v5)

```
DNS Phase:          6-10 seconds  (was 2-3 minutes)
Port Scan:         30-60 seconds  (target-dependent)
Web Enumeration:    1-5 minutes   (concurrent)
Vulnerability Scan: 3-10 minutes  (nuclei, nikto)
════════════════════════════════
TOTAL:             5-20 minutes   (for typical web app)

Total runtime budget: 30 minutes (configurable)
```

---

## Debug Mode: If Something Goes Wrong

```bash
# 1. Check decision log
cat scan_results_*/execution_report.json | jq '.execution_plan'

# 2. Check tool outputs
ls scan_results_*/*.txt
cat scan_results_*/nmap_quick.txt

# 3. Check cache state
cat scan_results_*/execution_report.json | jq '.discovery'

# 4. Check decision reasons
cat scan_results_*/execution_report.json | jq '.execution_plan[] | select(.status!="SUCCESS")'

# 5. Trace signal flow
grep "SIGNAL\|BLOCKED\|SKIPPED" scan_results_*/scan.log
```

---

## Key Files (What to Modify When)

```
Adding new tool?        → execution_paths.py (add to plan)
New signal type?        → _classify_signal() in automation_scanner_v2.py
New decision rule?      → _should_run() in automation_scanner_v2.py
Parser for tool output? → tool_parsers.py
New cache attribute?    → cache_discovery.py
Gating logic?           → execution_paths.py (requires/optional)
```

---

## Questions & Answers

**Q: Why doesn't whatweb block nuclei?**  
A: Because nuclei depends on web_target (user input), not on whatweb output. whatweb is optional intelligence.

**Q: What if nmap finds no ports?**  
A: nmap returns NEGATIVE_SIGNAL, downstream tools (nikto, sqlmap) skip appropriately.

**Q: How does Nikto rc=141 work now?**  
A: rc=141 is SIGPIPE (partial success). Treated same as rc=0 if stdout has findings.

**Q: Can I add my own tool?**  
A: Yes. Add to execution_paths.py, handle parsing in tool_parsers.py, define requires/optional/produces.

**Q: What if I want to force a tool to run?**  
A: Use policy: DecisionLedger marks tools as allowed/denied before execution.

**Q: How accurate is discovery summary?**  
A: 100%. Every tool populates cache.add_endpoint(), cache.add_port(), etc. Summary reflects reality.

---

*v5 Quick Reference - January 9, 2026*
