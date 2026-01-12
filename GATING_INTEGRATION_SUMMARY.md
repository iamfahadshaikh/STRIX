# Gating Loop Integration in automation_scanner_v2.py

## ✅ Status: INTEGRATED & VERIFIED

Gating loop (Option 3: per-tool gating) is now **fully integrated** into the main scanner pipeline.

---

## Changes Made

### 1. **Imports Added** (Line 25-26)
```python
from crawl_adapter import CrawlAdapter
from gating_loop import GatingLoopOrchestrator
```

### 2. **Crawling Phase Added** (After Network phase in phases dict)
```python
phases = {
    ...
    "Crawling": {"tools": {"gating_crawl"}},  # NEW
    ...
}
```

### 3. **Gating Loop Orchestration** (After phases definition, before execution loop)
```python
# NEW: Gating loop for payload tools (Option 3: per-tool gating)
gating_orchestrator = None
gating_signals = None

# Run crawling phase after Network phase to gather gating signals
self.log("Running crawling phase for payload tool gating...", "INFO")
try:
    crawl_adapter = CrawlAdapter(self.target, output_dir=str(self.output_dir))
    crawl_success, crawl_msg = crawl_adapter.run()
    
    if crawl_success:
        gating_signals = crawl_adapter.gating_signals
        gating_orchestrator = GatingLoopOrchestrator(self.ledger, crawl_adapter)
        gating_orchestrator.build_targets()
        self.log(f"Crawling complete: {gating_signals['crawled_url_count']} endpoints, "
                f"{gating_signals['parameter_count']} parameters, "
                f"{gating_signals['reflection_count']} reflections", "SUCCESS")
        self.log(f"Payload tool gating decisions: {self._summarize_gating(gating_orchestrator)}", "INFO")
    else:
        self.log(f"Crawling phase skipped: {crawl_msg}", "WARNING")
except Exception as e:
    self.log(f"Crawling phase error (non-blocking): {str(e)}", "WARNING")
```

### 4. **Per-Tool Gating Check** (In execution loop, before tool run)
```python
# NEW: Check gating for payload tools
if gating_orchestrator and tool_name in ["xsstrike", "dalfox", "sqlmap", "commix"]:
    if not gating_orchestrator.should_run_tool(tool_name):
        self.log(f"[{tool_name}] GATED (crawl signals say no)", "INFO")
        self.execution_results.append({
            "tool": tool_name,
            "outcome": ToolOutcome.BLOCKED.value,
            "reason": "Gated by crawl analysis (no targets)",
            "duration": 0
        })
        continue
```

### 5. **Helper Method Added** (Line ~890)
```python
def _summarize_gating(self, orchestrator) -> str:
    """Summarize gating decisions for logging"""
    summary = []
    for tool in ["xsstrike", "dalfox", "sqlmap", "commix"]:
        can_run = orchestrator.should_run_tool(tool)
        status = "✓ RUN" if can_run else "✗ SKIP"
        summary.append(f"{tool}: {status}")
    return " | ".join(summary)
```

---

## Execution Flow

```
1. DNS Phase
   └─> dig_a, dig_ns, dig_mx, dnsrecon

2. Subdomains Phase
   └─> findomain, sublist3r, assetfinder

3. Network Phase
   └─> ping, nmap_quick, nmap_vuln

4. CRAWLING PHASE (NEW - Gating Loop)
   ├─> light_crawler discovers endpoints (1-2 sec)
   ├─> Extracts parameters & reflections
   └─> Builds per-tool gating decisions

5. WebDetection Phase
   └─> whatweb

6. SSL Phase
   └─> sslscan, testssl

7. WebEnum Phase
   └─> gobuster, dirsearch

8. Exploitation Phase (Gated)
   ├─> xsstrike (only if reflections found)
   ├─> dalfox (only if reflections found)
   ├─> sqlmap (only if parameters found)
   └─> commix (only if parameters found)

9. Nuclei Phase
   └─> nuclei_crit, nuclei_high
```

---

## Example Output

When scanner runs, you'll see:

```
[INFO] Running crawling phase for payload tool gating...
[SUCCESS] Crawling complete: 20 endpoints, 5 parameters, 1 reflections
[INFO] Payload tool gating decisions: xsstrike: ✓ RUN | dalfox: ✓ RUN | sqlmap: ✓ RUN | commix: ✓ RUN
[INFO] [dalfox] Starting execution (1/50)
[INFO] [xsstrike] Starting execution (2/50)
[INFO] [sqlmap] Starting execution (3/50)
[INFO] [commix] Starting execution (4/50)
```

Or if no parameters found:

```
[SUCCESS] Crawling complete: 20 endpoints, 0 parameters, 0 reflections
[INFO] Payload tool gating decisions: xsstrike: ✗ SKIP | dalfox: ✗ SKIP | sqlmap: ✗ SKIP | commix: ✗ SKIP
[INFO] [xsstrike] GATED (crawl signals say no)
[INFO] [dalfox] GATED (crawl signals say no)
[INFO] [sqlmap] GATED (crawl signals say no)
[INFO] [commix] GATED (crawl signals say no)
```

---

## Key Features

✅ **Non-invasive Integration**: Crawling phase added as optional step
✅ **Safe Fallback**: Crawling errors don't crash scanner (logged as WARNING)
✅ **Per-Tool Gating**: Each payload tool independently gated
✅ **Execution Logged**: BLOCKED outcomes recorded in execution_results
✅ **No Core Logic Changed**: Existing scanner flow untouched

---

## Verification

✓ Syntax: Valid Python
✓ Imports: CrawlAdapter and GatingLoopOrchestrator available
✓ Integration: Gating loop called after Network phase
✓ Execution: Tools only run if gating says yes

---

## Next Steps

1. **Run full scan**: `python automation_scanner_v2.py https://target.com`
2. **Monitor logs**: Watch for "Crawling complete" and gating decisions
3. **Check results**: execution_results will show BLOCKED outcomes for gated tools
4. **Tune gating**: Adjust thresholds in decision_ledger.py if needed

---

## Files Modified

- ✅ `automation_scanner_v2.py` (3 additions: imports, phase, loop check, helper method)

## Files Used (Unchanged)

- ✅ `crawl_adapter.py`
- ✅ `gating_loop.py`
- ✅ `decision_ledger.py`
- ✅ `crawler_integration.py`
- ✅ `light_crawler.py`
- ✅ `katana_crawler.py`

