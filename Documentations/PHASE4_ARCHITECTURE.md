# Phase 4: Production-Grade Vulnerability Assessment Engine

**Status**: Planning phase
**Objective**: Transform from advanced scanner → enterprise-ready platform
**Timeline**: ~8-12 hours (7 sequential components)

---

## Vision

**From**: Tool that finds vulnerabilities
**To**: Deterministic, explainable, auditable platform
- Repeatable scans (capture + replay)
- Safe for CI/CD pipelines
- Business-readable reports
- Enterprise-grade stability

---

## Phase 4 Components (7 Sequential Tasks)

### 1. Traffic Capture & Replay (task_traffic_capture.py)
**Purpose**: Record all HTTP traffic, enable deterministic replay

**What gets captured**:
```
Request:
  - URL, method, headers, cookies, body
  - Tool that generated it (sqlmap, dalfox, etc.)
  - Timestamp, response_time_ms
  
Response:
  - Status code, headers, body (first 10KB)
  - Content-Type, Set-Cookie headers
  - Error indicators, redirect targets
```

**Replay Mode**:
- Load stored traffic
- Skip API discovery (use cached schemas)
- Skip crawling (use captured endpoints)
- Skip payload generation (use recorded payloads)
- Compare outputs → detect deviations

**Key Class**: `TrafficCapture`
- `capture_request(method, url, headers, body, tool_name)`
- `capture_response(status, headers, body, execution_time_ms)`
- `get_session()` → all captured HTTP exchanges
- `export_har()` → HAR format (browser standard)
- `replay_mode()` → True/False flag

**Output**:
```json
{
  "session_id": "scan_20260112_143022",
  "captured_exchanges": 247,
  "start_time": "2026-01-12T14:30:22Z",
  "end_time": "2026-01-12T14:35:45Z",
  "endpoints": 45,
  "payloads_tested": 1203
}
```

---

### 2. Regression & Baseline Comparison (regression_engine.py)
**Purpose**: Compare scans, detect changes

**Baseline snapshot**:
```
Snapshot (immutable):
  {
    "scan_id": "baseline_20260101",
    "timestamp": "2026-01-01T00:00:00Z",
    "endpoints": {endpoint -> [params]},
    "findings": {(endpoint, param, type) -> risk_severity},
    "hash": "sha256_of_all_findings"
  }
```

**Delta Report**:
```
NEW:         Findings not in baseline
PERSISTING:  Same (endpoint, param, type) with same severity
REGRESSED:   Same finding, severity INCREASED
FIXED:       Finding in baseline but NOT in current scan
IMPROVED:    Same finding, severity DECREASED
```

**Key Class**: `RegressionEngine`
- `create_baseline(scan_id, findings, endpoints)`
- `compare_to_baseline(baseline_id, current_scan)`
- `get_delta_report()` → {NEW: [...], FIXED: [...], REGRESSED: [...]}
- `calculate_change_score()` → 0-100 (lower = fewer changes = stable)
- `detect_false_positive_reduction()` → Fixed vulns with tool_count=1 are suspicious

**Output**:
```json
{
  "baseline_id": "baseline_20260101",
  "current_scan_id": "scan_20260112",
  "delta": {
    "NEW": [
      {
        "endpoint": "/api/users",
        "parameter": "id",
        "vulnerability_type": "SQL_INJECTION",
        "risk_severity": "CRITICAL"
      }
    ],
    "FIXED": [...],
    "REGRESSED": [...],
    "PERSISTING": [...]
  },
  "stability_score": 92,
  "summary": "2 new findings, 1 regressed, 3 fixed"
}
```

---

### 3. CI/CD Integration (ci_integration.py)
**Purpose**: Safe execution in automated pipelines

**Headless Mode**:
```python
scanner = VAPTScanner(headless=True)
# No interactive prompts
# No UI initialization
# JSON-only output
# Deterministic exit codes
```

**Exit Codes**:
```
0   = All findings are INFO
1   = Has MEDIUM findings (warn, don't fail)
2   = Has HIGH findings (fail build)
3   = Has CRITICAL findings (fail build, urgent)
4   = Scanner error (tool crash, timeout)
5   = Configuration error
```

**Build Gates**:
```python
if exit_code >= 2:
    fail_build("HIGH or CRITICAL findings")
elif exit_code == 1:
    warn_build("MEDIUM findings, review before merge")
else:
    pass_build("No actionable findings")
```

**Key Class**: `CIIntegration`
- `set_headless_mode(enabled: bool)`
- `get_exit_code() -> int`
- `export_json_only()` → no HTML, no graphs
- `set_failure_threshold(severity: str)` → "CRITICAL" | "HIGH" | "MEDIUM"
- `export_sarif()` → GitHub-native format
- `export_junit()` → Jenkins format

**Output**:
```
SARIF Format (GitHub native):
{
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "INJECTION/SQL",
          "level": "error",
          "message": {"text": "SQL injection in /api/users?id"},
          "locations": [...]
        }
      ]
    }
  ]
}
```

---

### 4. Risk Aggregation & Business View (risk_aggregation.py)
**Purpose**: Convert technical findings into business metrics

**Aggregation Levels**:

**Per Endpoint**:
```
/api/users:
  ├─ Severity: HIGH (max of all params)
  ├─ Findings: 3
  ├─ Risk Score: 8.2/10
  └─ Params:
      ├─ id: SQL_INJECTION (CRITICAL)
      ├─ limit: Integer overflow (LOW)
      └─ sort: OWASP_A03 (MEDIUM)
```

**Per OWASP Category**:
```
A03_INJECTION:
  ├─ Count: 12
  ├─ Severity: 3 CRITICAL, 5 HIGH, 4 MEDIUM
  ├─ Endpoints: /api/users, /api/posts, /api/comments
  └─ Recommended Fix: Input validation + parameterized queries
```

**Per Application**:
```
Total Risk: 7.8/10
├─ CRITICAL: 2 findings
├─ HIGH: 5 findings
├─ MEDIUM: 8 findings
├─ Trend: ↑ (was 7.2 last scan)
└─ Recommendation: Urgent review of injection vulns
```

**Key Class**: `RiskAggregator`
- `aggregate_by_endpoint(findings) -> Dict`
- `aggregate_by_owasp(findings) -> Dict`
- `aggregate_by_app(findings) -> Dict`
- `calculate_business_risk_score() -> float (0-10)`
- `get_trend_analysis(baseline, current) -> Dict`
- `recommend_priority_order() -> List[Finding]` (by business impact)

**Output**:
```json
{
  "business_risk_score": 7.8,
  "endpoints_at_risk": 12,
  "vulnerabilities_by_severity": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 8,
    "LOW": 15,
    "INFO": 23
  },
  "owasp_breakdown": {
    "A03_INJECTION": 12,
    "A01_BROKEN_ACCESS_CONTROL": 4,
    ...
  },
  "trend": "INCREASING",
  "trend_change": 0.6,
  "critical_next_steps": [...]
}
```

---

### 5. Scan Profiles Manager (scan_profiles.py)
**Purpose**: Standardized, repeatable scan configurations

**5 Profiles**:

```python
PROFILE_RECON_ONLY = {
    "name": "recon-only",
    "tools": ["light_crawler"],
    "endpoints_max": None,
    "payloads_per_endpoint": 0,  # No payloads
    "timeout_minutes": 5,
    "authentication": False,
    "api_discovery": True,
    "depth": "shallow",
    "description": "Discover endpoints only, no testing"
}

PROFILE_SAFE_VA = {
    "name": "safe-va",
    "tools": ["dalfox", "nuclei"],  # No SQL-breaking tools
    "endpoints_max": 100,
    "payloads_per_endpoint": 10,
    "timeout_minutes": 15,
    "authentication": False,
    "api_discovery": True,
    "depth": "medium",
    "payload_categories": ["XSS", "OPEN_REDIRECT", "INFO_DISCLOSURE"],
    "description": "Safe testing (no data destruction)"
}

PROFILE_AUTH_VA = {
    "name": "auth-va",
    "tools": ["dalfox", "nuclei", "sqlmap"],
    "endpoints_max": 200,
    "payloads_per_endpoint": 20,
    "timeout_minutes": 30,
    "authentication": True,
    "api_discovery": True,
    "depth": "deep",
    "credentials": ["admin", "user"],
    "description": "Full testing with authentication"
}

PROFILE_CI_FAST = {
    "name": "ci-fast",
    "tools": ["nuclei"],  # Template-only, predictable
    "endpoints_max": 50,
    "payloads_per_endpoint": 5,
    "timeout_minutes": 5,
    "authentication": False,
    "api_discovery": False,  # Use cached APIs
    "depth": "shallow",
    "description": "Fast CI/CD scan (5 minutes)"
}

PROFILE_FULL_VA = {
    "name": "full-va",
    "tools": ["dalfox", "sqlmap", "commix", "nuclei", "burp"],
    "endpoints_max": None,
    "payloads_per_endpoint": 50,
    "timeout_minutes": 120,
    "authentication": True,
    "api_discovery": True,
    "depth": "deep",
    "credentials": ["admin", "user", "guest"],
    "description": "Comprehensive vulnerability assessment"
}
```

**Key Class**: `ScanProfileManager`
- `get_profile(name: str) -> Profile`
- `create_custom_profile(config: Dict) -> Profile`
- `validate_profile(profile: Profile) -> bool`
- `apply_profile_to_scanner(profile: Profile, scanner: VAPTScanner)`
- `list_profiles() -> List[str]`

**Usage**:
```python
profile = ScanProfileManager.get_profile("ci-fast")
scanner.apply_profile(profile)
scanner.run()  # Guaranteed <5 minutes
```

---

### 6. Engine Hardening & Resilience (engine_resilience.py)
**Purpose**: Never hang, gracefully degrade on failure

**Tool Crash Isolation**:
```
Tool Process:
  ├─ Subprocess with timeout
  ├─ Memory limit
  ├─ CPU limit
  └─ If timeout/crash → mark tool_result as TIMEOUT, continue

Report includes:
  "tools_completed": ["dalfox", "nuclei"],
  "tools_failed": [
    {"tool": "sqlmap", "reason": "Timeout after 30s"},
    {"tool": "commix", "reason": "Out of memory"}
  ]
```

**Partial Failure Tolerance**:
```
If API discovery fails:   Use cached schemas
If auth validation fails: Continue unauthenticated
If tool crashes:         Continue with other tools
If endpoint hangs:       Skip endpoint, continue
```

**Resume from Checkpoint**:
```
Checkpoint every 5 endpoints:
  {
    "scan_id": "scan_20260112",
    "checkpoint": 15,
    "endpoints_completed": [...],
    "findings_so_far": [...],
    "timestamp": "2026-01-12T14:45:00Z"
  }

If scanner dies:
  scanner = VAPTScanner.resume_from_checkpoint(scan_id)
  # Continues from endpoint 16
```

**Key Class**: `EngineResilience`
- `run_tool_isolated(tool, args, timeout_sec) -> ToolResult`
- `create_checkpoint(scan_id, endpoint_count, findings)`
- `resume_from_checkpoint(scan_id) -> Scanner`
- `get_tool_health_status() -> Dict` (which tools crashed)
- `set_timeout_enforcement(enabled: bool)`
- `set_memory_limit_mb(limit: int)`

**Output**:
```json
{
  "scan_completed": true,
  "completion_percentage": 94,
  "tools_used": 5,
  "tools_completed": 4,
  "tools_failed": [
    {
      "tool": "commix",
      "reason": "timeout",
      "endpoints_tested": 32
    }
  ],
  "findings_collected": 47,
  "partial_failure_recovery": true
}
```

---

### 7. Final Documentation & Contracts (PHASE4_CONTRACTS.md)
**Purpose**: Lock down promises, non-goals, use-cases

**Tool Guarantees**:
```
✅ Deterministic:     Same input → same output (unless external changes)
✅ Repeatable:        Captures traffic for audit trail
✅ Safe:              No credential storage, no privilege escalation
✅ Auditable:         All findings traceable to tool + payload
✅ Explainable:       Every finding has evidence
✅ Time-bounded:      Max 2 hours per scan (hard timeout)
✅ Partial-failure:   Works even if tools crash
✅ CI-safe:           Exit codes, no hanging
```

**Explicit Non-Goals**:
```
❌ Exploit execution (no actual data deletion)
❌ Privilege escalation (no account hijacking)
❌ Credential attacks (no brute force)
❌ WAF evasion (no obfuscation attempts)
❌ Zero-day detection (template + known CVE only)
❌ Data exfiltration (only test, no download)
❌ Denial of service (no resource depletion)
```

**Supported Use Cases**:
```
✅ Development environment testing
✅ Pre-production validation
✅ CI/CD gate checks
✅ Compliance audits
✅ Enterprise vulnerability management
✅ SaaS platform backend
```

**Not Supported**:
```
❌ Production systems (no traffic disruption risk)
❌ Air-gapped networks (requires internet access)
❌ Real-time threat response (batch processing only)
❌ Zero-day research (known vulns only)
```

---

## Implementation Order (Strict Sequence)

```
Task 1: Planning ✅ [This document]
        ↓
Task 2: Traffic Capture & Replay
        ├─ HTTP capture
        ├─ Replay mode
        └─ HAR export
        ↓
Task 3: Regression & Baseline
        ├─ Baseline snapshots
        ├─ Delta detection
        └─ Trending
        ↓
Task 4: CI/CD Integration
        ├─ Headless mode
        ├─ Exit codes
        └─ Format exports (SARIF, JUnit)
        ↓
Task 5: Risk Aggregation
        ├─ Per-endpoint aggregation
        ├─ Per-OWASP aggregation
        └─ Business view
        ↓
Task 6: Scan Profiles
        ├─ 5 predefined profiles
        ├─ Custom profile support
        └─ Profile application
        ↓
Task 7: Engine Hardening
        ├─ Tool isolation
        ├─ Timeout enforcement
        ├─ Partial failure tolerance
        └─ Checkpoint/resume
        ↓
Task 8: Testing
        ├─ Unit tests (all components)
        ├─ Integration tests
        └─ Stability tests (tool crashes, timeouts)
        ↓
Task 9: Documentation & Contracts
        ├─ Tool guarantees
        ├─ Non-goals
        ├─ Use cases
        └─ Legal-safe behavior
```

---

## Integration with Existing Phases

**Phase 1-3** (Already Complete):
- Crawling + graph
- Gating + tool execution
- Finding correlation
- Risk scoring

**Phase 4** Layers On Top:
```
┌─ Phase 4: Production Maturity
│  ├─ Traffic capture (deterministic replay)
│  ├─ Regression detection (baseline comparison)
│  ├─ CI/CD gates (exit codes, formats)
│  ├─ Risk aggregation (business view)
│  ├─ Scan profiles (standardized configs)
│  ├─ Engine hardening (crash isolation, checkpoint)
│  └─ Contracts (guaranteed behavior)
│
├─ Phase 3: Professional Assessment
│  ├─ Finding correlation (multi-tool)
│  ├─ API discovery (Swagger/OpenAPI)
│  ├─ Authentication (multi-credential)
│  └─ Risk engine (5-factor scoring)
│
├─ Phase 2: Gating & Orchestration
│  ├─ Endpoint graph
│  ├─ Confidence scoring
│  ├─ Tool gating
│  └─ OWASP mapping
│
└─ Phase 1: Core Discovery
   ├─ Crawling
   ├─ Parameter extraction
   └─ Endpoint discovery
```

---

## Success Metrics for Phase 4

- [x] Repeatable scans (capture + replay)
- [ ] Baseline comparison (NEW|FIXED|REGRESSED)
- [ ] CI/CD safe (exit codes, JSON output)
- [ ] Risk aggregation (business-readable)
- [ ] Scan profiles (5 standardized)
- [ ] Engine stability (zero hangs, partial failure tolerance)
- [ ] Documented guarantees (contracts locked)
- [ ] 100% test coverage

---

## Estimated Timeline

| Task | Hours | Status |
|------|-------|--------|
| 1. Planning | 0.5 | ✅ Complete |
| 2. Traffic Capture | 2 | ⏳ Next |
| 3. Regression Engine | 2 | ⏳ Next |
| 4. CI/CD Integration | 1.5 | ⏳ Next |
| 5. Risk Aggregation | 1.5 | ⏳ Next |
| 6. Scan Profiles | 1 | ⏳ Next |
| 7. Engine Hardening | 2 | ⏳ Next |
| 8. Testing | 2 | ⏳ Next |
| 9. Documentation | 1 | ⏳ Next |
| **TOTAL** | **13.5** | ⏳ In Progress |

---

## End State

**From**: Advanced scanner
**To**: Enterprise Vulnerability Assessment Platform Core

Ready for:
- ✅ SaaS platform embedding
- ✅ Enterprise tool integration
- ✅ CI/CD pipeline integration
- ✅ Regulatory compliance
- ✅ Audit trails
- ✅ Repeatable assessments

**Promise**: Deterministic, explainable, auditable vulnerability assessment.
