# Signal-Driven Engine: How It Works Now

**Framework**: Input → Discovery Cache → Decision Layer → Execution → Findings Registry

---

## 1. Input Trust Model

```python
profile = TargetProfile.from_target("https://example.com")
# User input is authoritative:
# - scheme: https (not waiting for discovery to confirm)
# - host: example.com
# - port: 443 (if https), 80 (if http)
# - is_web_target: True (has URL)
```

**Decision Context**:
```python
ctx = {
    "web_target": bool(profile.is_web_target),      # User said it's web
    "https": profile.is_https,                      # User provided scheme
    "reachable": True,                              # Assume yes until proven no
    "ports_known": len(cache.discovered_ports) > 0,
    "endpoints_known": cache.has_endpoints(),
    "live_endpoints": cache.has_live_endpoints(),
    "params_known": cache.has_params(),
    ...
}
```

**No waiting for discovery to validate user input.** User says HTTPS → we trust it.

---

## 2. Discovery Cache: Growing Signal Store

```python
cache = DiscoveryCache()

# Tools populate cache as they run:
cache.add_endpoint("/admin")           # From gobuster
cache.add_live_endpoint("/api/v1")     # HTTP 200 confirmed
cache.add_param("id")                  # From any tool
cache.add_port(8080)                   # From nmap
cache.add_reflection("search")         # XSS candidate
cache.add_subdomain("api.example.com") # From enumeration

# Query for planning:
cache.has_live_endpoints()   # True if any HTTP 200 endpoints
cache.get_discovered_ports() # [22, 80, 443, 8080]
cache.summary()              # "Endpoints: 15, Live: 8, Params: 42, ..."
```

**Each discovery updates planning context → next tools gate accordingly.**

---

## 3. Signal Classification: No More Ambiguity

```python
def _classify_signal(tool, stdout, stderr, rc):
    """
    POSITIVE: Tool found something actionable
    NO_SIGNAL: Tool ran but found nothing useful
    NEGATIVE_SIGNAL: Tool confirmed absence (blocks downstream)
    """
    
    # whatweb examples:
    if tool == "whatweb":
        if "Apache" in stdout:
            return "POSITIVE"  # Tech found
        else:
            return "NO_SIGNAL"  # No tech found ≠ no web service
    
    # nmap examples:
    if tool == "nmap_quick":
        if " open " in stdout:
            return "POSITIVE"
        else:
            return "NEGATIVE_SIGNAL"  # No ports = confirmed absence
    
    # Others:
    if stdout.strip():
        return "POSITIVE"
    return "NO_SIGNAL"
```

**whatweb POSITIVE = tech detected** (high confidence CMS)  
**whatweb NO_SIGNAL = no recognized tech** (still could be web service)  
**nmap NEGATIVE_SIGNAL = no ports open** (confirmed absent)

---

## 4. Decision Layer: Clean Gating

```python
def _should_run(tool, plan_item):
    """
    Returns: (DecisionOutcome, reason)
    - BLOCK: Missing required input (hard stop)
    - SKIP: Won't produce value (budget/redundancy)
    - ALLOW: Ready to execute
    """
    
    # Example: nuclei
    meta = {
        "requires": {"web_target"},
        "optional": {"live_endpoints", "endpoints_known"},
        "produces": {"web_findings"},
    }
    
    ctx = _build_context()  # Fresh snapshot of capabilities
    
    # Check: Do we have web_target?
    if not ctx["web_target"]:
        return (BLOCK, "missing required capability: web_target")
    
    # Check: Is runtime budget sufficient?
    if 600 > remaining_time:  # nuclei worst-case
        return (SKIP, "insufficient runtime budget")
    
    # Check: Do we already have all produces?
    if ctx.get("web_findings", False):
        return (SKIP, "no new signal expected")
    
    # All clear:
    return (ALLOW, "ready")
```

**No hidden state dependencies. All decisions explicit.**

---

## 5. Consolidated DNS (Example of De-duplication)

### Before (Root Domain):
```
dig_a        → "dns_records"
dig_ns       → "dns_records"
dig_mx       → "dns_records"
dig_aaaa     → "dns_records"
dnsrecon     → "dns_records"  ← All produce same signal!
Total: ~2.5 min for redundant queries
```

### After (Root Domain):
```
dnsrecon     → "dns_records"  ← One tool, all record types
Total: ~6s for A/NS/MX/AAAA/TXT
```

### Subdomain (Verification Only):
```
dig_a        → DNS verify
dig_aaaa     → DNS verify (both quick)
Total: ~2s
```

**Result**: DNS phase → 90% faster, zero signal loss.

---

## 6. Refactored _run_tool(): Focused Responsibilities

### Before:
```python
def _run_tool(self, plan_item):
    # 180 lines doing:
    # - subprocess execution
    # - return code interpretation
    # - output filtering
    # - finding extraction
    # - cache population
    # - outcome determination
    # ALL IN ONE METHOD ❌
```

### After:
```python
def _run_tool(self, plan_item):
    # Orchestrate focused helpers:
    
    stdout, stderr, rc = self._execute_tool_subprocess(
        command, timeout
    )
    
    outcome, status = self._classify_execution_outcome(
        tool, rc, stdout, stderr
    )
    
    filtered = self._filter_actionable_stdout(tool, stdout)
    
    self._extract_and_cache_findings(
        tool, filtered, stderr, profile
    )
    
    return {"tool": tool, "status": status, "outcome": outcome}
```

**Each helper does one thing well. Easy to test, debug, extend.**

---

## 7. Real Example: whatweb → nuclei Flow

### Scenario 1: whatweb finds WordPress
```
1. whatweb runs:
   OUTPUT: WordPress 6.1
   SIGNAL: POSITIVE (tech detected)
   CACHE: tech_stack_detected = True
   
2. nuclei runs:
   REQUIRES: {web_target}   ← Already satisfied (user input)
   OPTIONAL: {live_endpoints, endpoints_known}
   STATUS: ALLOW (no live_endpoints needed)
   DECISION: RUN (might scope to live endpoints if available)
```

### Scenario 2: whatweb finds nothing
```
1. whatweb runs:
   OUTPUT: "" (empty, no recognized tech)
   SIGNAL: NO_SIGNAL (not NEGATIVE_SIGNAL)
   CACHE: tech_stack_detected = False
   
2. nuclei runs:
   REQUIRES: {web_target}   ← Still satisfied
   OPTIONAL: {live_endpoints, endpoints_known}
   STATUS: ALLOW (doesn't care whatweb found nothing)
   DECISION: RUN (will test base URL directly)
```

**Before**: Scenario 2 → nuclei BLOCKED  
**After**: Scenario 2 → nuclei RUNS

---

## 8. Outcome Types (Clear Semantics)

```python
class ToolOutcome(Enum):
    SUCCESS_WITH_FINDINGS = "Has actionable data"
    SUCCESS_NO_FINDINGS = "Ran OK, nothing found"
    TIMEOUT = "Exceeded runtime"
    EXECUTION_ERROR = "Tool failed (exit code, prereq missing, etc.)"

class DecisionOutcome(Enum):
    ALLOW = "Ready to execute"
    BLOCK = "Prerequisite missing"
    SKIP = "Not worth running"
    DENIED = "Policy forbids"  # (from DecisionLedger)
```

**Status** (what happened):
- SUCCESS
- PARTIAL (e.g., SIGPIPE rc=141)
- FAILED
- BLOCKED / SKIPPED / DENIED

**Outcome** (what to record):
- SUCCESS_WITH_FINDINGS → new intelligence gathered
- SUCCESS_NO_FINDINGS → tool OK, nothing new
- TIMEOUT → budget issue
- EXECUTION_ERROR → tool problem

---

## 9. Entry Point: How to Use

```python
from automation_scanner_v2 import AutomationScannerV2

# Initialize (user input is authoritative):
scanner = AutomationScannerV2(
    target="https://example.com",
    output_dir="scan_results",
    skip_tool_check=False,  # Install tools if needed
    mode="full"  # Only mode now (gate mode removed)
)

# Run (signal-driven orchestration):
results = scanner.scan()

# Results structure:
{
    "target": "example.com",
    "findings": [...],  # Deduplicated, correlated
    "intelligence": {...},  # Confidence scores
    "discovery": {
        "endpoints": ["/admin", "/api/v1", ...],
        "live_endpoints": ["/", "/api/v1"],
        "parameters": ["id", "search", "token"],
        "ports": [22, 80, 443, 8080],
        "subdomains": ["api.example.com", ...]
    },
    "execution_plan": [...],
    "decision_log": [...]
}
```

---

## 10. Key Principles (Going Forward)

1. **Trust User Input**: scheme, host, port from command-line are ground truth
2. **No Leaky Coupling**: Tool A's output doesn't implicitly gate Tool B
3. **One Signal Per Type**: Remove duplicate detection (1 DNS tool, not 5)
4. **Explicit Gating**: All decisions via (requires, optional, produces)
5. **Clear Terminology**: ALLOW/BLOCK/SKIP/DENY mean specific things
6. **Single Responsibility**: Each method does one job well
7. **Defensive Defaults**: Tools run unless explicitly blocked by missing prerequisite

---

## What This Enables

✅ Real internal assessments (tool starvation gone)  
✅ Multi-target batch scans (predictable behavior)  
✅ Custom intelligence layers (signal is clean)  
✅ Easy feature additions (helpers are composable)  
✅ Debugging (every decision logged with reason)  
✅ Confidence scoring (correlation engine reads clean signals)

**This is v5. Ready for production internal assessments.**
