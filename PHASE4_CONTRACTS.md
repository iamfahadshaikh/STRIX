# Phase 4: Platform Contracts & Guarantees

**Status**: Production-Ready | **Version**: 4.0.0  
**Created**: 2026-01-12 | **Last Updated**: 2026-01-12

---

## Executive Summary

Phase 4 transforms the VAPT scanner from a technical tool into an enterprise-ready platform. This document locks down the guarantees, non-goals, and intended use cases.

### The Core Promise

> **One Promise**: Your scan results are **deterministic, explainable, and auditable**. Run the same scan twice, get the same results. Every finding is traceable to source tools. Every scan is resumable.

---

## Part 1: Guarantees (What We Commit To)

### 1.1 Deterministic Results

**Guarantee**: When you run the same scan with the same inputs, you get the same outputs.

**What This Means**:
- Same target + same profile + same credentials = identical findings
- Results are reproducible for validation, audits, and regression testing
- Ordering of results is deterministic (sorted by severity then endpoint)

**How We Achieve This**:
- Traffic capture: All HTTP requests/responses recorded
- Replay mode: Subsequent runs use recorded data when available
- Baseline comparison: Differences highlighted explicitly
- No randomization: No random delays, no random payload ordering

**What This Doesn't Cover**:
- Live targets may change between scans (legitimate NEW findings are expected)
- Network issues may cause timeouts (handled via partial failure tolerance)
- Tool updates may affect results (version pinning recommended)

---

### 1.2 Complete Explainability

**Guarantee**: Every finding is traceable to its source.

**Traceability Chain**:
```
Finding → Tool(s) that discovered it → Payload used → HTTP exchange captured → Evidence
                   ↓
        Finding correlator validates agreement
                   ↓
        Risk engine assigns severity + OWASP category
                   ↓
        Regression engine compares to baseline
```

**What You Get**:
- Tool agreement tracking (1 tool vs 3 tools vs consensus)
- Payload registry (exact payload that triggered finding)
- HTTP exchange history (request + response captured)
- Confidence scoring (how sure are we of this finding)
- OWASP mapping (why this matters)

**Audit Trail**:
- Session ID: Trace all exchanges to one scan
- Endpoint fingerprint: Know exactly what was tested
- Tool logs: See tool-specific evidence
- Delta report: Understand what changed since last scan

---

### 1.3 Always Finish (Never Hang)

**Guarantee**: Scans always complete or fail gracefully, never hang indefinitely.

**Mechanisms**:
- **Global timeout**: Configurable scan timeout (default 1 hour)
- **Per-tool timeout**: Each tool has independent timeout (default 2 minutes)
- **Checkpoint/resume**: Save progress every endpoint, resume from last checkpoint
- **Partial failure tolerance**: If 1 tool crashes, others continue
- **Graceful degradation**: Miss findings, but don't hang

**Maximum Wait Times**:
| Component | Default | Configurable |
|-----------|---------|--------------|
| Per-tool execution | 120 seconds | Yes |
| Per-endpoint crawl | 30 seconds | Yes |
| Global scan | 1 hour | Yes |
| Response read | 10 seconds | Yes |

**What Happens on Timeout**:
1. Tool is isolated and killed
2. Endpoint is marked as partial (some tools succeeded)
3. Scanning continues with next endpoint
4. Report includes timeout info
5. Exit code reflects partial completion (not failure)

---

### 1.4 Transparent Failures

**Guarantee**: You always know what went wrong and why.

**Failure Reporting**:
- **Crash report**: Which tools crashed, when, why
- **Timeout report**: Which endpoints timed out, which tool, how long
- **Partial results**: What succeeded, what failed
- **Resilience score**: Overall scan health (0-100%)
- **Resume capability**: Can retry from checkpoint

**Error Categories**:
```
Tool crash          → Isolate, continue, log
Tool timeout        → Kill gracefully, continue
Network error       → Retry with backoff, log
Authentication fail → Report and skip authenticated tests
Rate limit          → Backoff and retry
```

---

### 1.5 Zero Surprise

**Guarantee**: No hidden behavior. No magic. Everything is configurable and auditable.

**What This Means**:
- All tools are listed before scan starts
- All payloads are logged before sending
- All network calls are captured
- Nothing runs in background after scan "completes"
- Export formats are standard (SARIF, JUnit, HAR, JSON)

**Visibility**:
- Scan profile printed before execution
- Real-time progress updates (endpoint count, tool status)
- Post-scan summary (findings, duration, tools used)
- Complete HTTP history (export as HAR for inspection in browser)

---

## Part 2: Non-Goals (What We Explicitly Don't Do)

### 2.1 Exploitation Payloads

**We Don't**: Create exploits or execute privileged operations.

**Specifically**:
- ❌ Delete files or data
- ❌ Execute system commands
- ❌ Modify application state (except info disclosure testing)
- ❌ Attempt privilege escalation exploits
- ❌ Run destructive payloads

**What We Do**: 
- ✅ Test for presence of vulnerabilities (detection)
- ✅ Collect information that proves presence
- ✅ Assess authentication bypass (read-only)
- ✅ Probe for IDOR (retrieve data you could access normally)

---

### 2.2 Evasion Techniques

**We Don't**: Use WAF evasion or IDS evasion tactics.

**Specifically**:
- ❌ Obfuscate payloads to evade WAF
- ❌ Randomize request timing to evade rate limits
- ❌ Use proxy rotation to evade detection
- ❌ Modify user-agent to impersonate legitimate clients
- ❌ Use HTTP protocol tricks to bypass security

**What We Do**:
- ✅ Straightforward scanning (what you'd do manually)
- ✅ Standard HTTP (RFC-compliant)
- ✅ Respect rate limits and implement backoff
- ✅ Be transparent about tool identity in headers

---

### 2.3 Advanced Exploits

**We Don't**: Implement advanced exploitation techniques.

**Specifically**:
- ❌ Zero-day exploits
- ❌ Complex multi-stage attacks
- ❌ Logic bomb creation
- ❌ Data exfiltration infrastructure
- ❌ Backdoor installation

**Why**: These are out of scope for vulnerability *assessment*. They're in scope for penetration *testing*, which is a different engagement model.

---

### 2.4 Legal Gray Areas

**We Don't**: Engage in legally ambiguous activities.

**Scope Boundary**:
- ✅ Test systems you own or have authorization for
- ❌ Test systems you don't have permission for
- ✅ Collect findings to remediate
- ❌ Collect data for competitive intelligence
- ✅ Report vulnerabilities responsibly
- ❌ Weaponize findings for attacks

---

## Part 3: Supported Use Cases

### 3.1 Internal Security Assessment

**Profile**: `auth-va` (full authenticated testing)

**Scenario**:
- You own the target system
- Authenticated access available (API key, session token)
- Goal: Comprehensive vulnerability assessment

**Guarantees**:
- Will test authentication logic thoroughly
- Will probe for IDOR/privilege escalation
- Will test all discovered endpoints
- Results deterministic and reproducible
- Safe for repeated runs (no data destruction)

**Typical Timeline**: 1-2 hours per target

---

### 3.2 Continuous Integration / CD Pipeline

**Profile**: `ci-fast` (rapid scanning)

**Scenario**:
- Integration with build pipeline
- Run on every commit or nightly
- Goal: Catch regressions quickly

**Guarantees**:
- Completes in ~30 minutes
- Exit codes suitable for build gates (fail on CRITICAL, warn on HIGH)
- SARIF output integrates with GitHub/GitLab
- JUnit output integrates with Jenkins/Azure Pipelines
- Partial failures don't block pipeline (fail only if critical findings)

**Typical Timeline**: 15-30 minutes per scan

---

### 3.3 Reconnaissance Only

**Profile**: `recon-only` (zero attacks)

**Scenario**:
- Explore target without permission yet
- Goal: Discover surface area, plan assessment
- May be used for lead generation (if authorized)

**Guarantees**:
- Zero active payloads (crawling only)
- No modification to target
- No exploitation attempts
- Safe to run anywhere, anytime
- Produces endpoint inventory

**Typical Timeline**: 5-15 minutes per target

---

### 3.4 Baseline & Regression Testing

**Scenario**:
- Create baseline scan at known-good state
- Run periodic scans to detect changes
- Goal: Identify new vulnerabilities or regressions

**Guarantees**:
- Baseline immutable (locked in version control)
- Delta report shows: NEW | FIXED | REGRESSED | IMPROVED | PERSISTING
- Trends tracked over time
- Suspicious fixes identified (single-tool fixes questioned)
- Deterministic comparison (same findings identified consistently)

**Typical Timeline**: Ongoing (baseline once, compare regularly)

---

### 3.5 Post-Remediation Verification

**Scenario**:
- Run scan, find vulnerabilities
- Developers fix issues
- Run same scan again to verify

**Guarantees**:
- Same profile → same coverage
- Regression engine shows: which vulnerabilities FIXED, which PERSISTING
- If finding still present after "fix", it's marked PERSISTING
- Audit trail of remediation process

**Typical Timeline**: Hours to weeks (depends on remediation speed)

---

## Part 4: Limitations & Caveats

### 4.1 Application Logic Vulnerabilities

**We Can't Detect**:
- Business logic bypasses (complex multi-step bypasses)
- Subtle authorization flaws (context-dependent access control)
- Time-of-check-time-of-use race conditions
- Information flow leaks (cross-user data exposure via timing)
- Workflow manipulation (bypassing sequence of steps)

**Why**: Requires understanding intended business logic, not just technical structure.

**Recommendation**: Use manual testing or logic-specific tools for these.

---

### 4.2 Performance Impact

**We May Cause**:
- Network load (many concurrent requests)
- Database load (queries triggered by payloads)
- Rate limiting (may get rate-limited, respect it)
- Transient service degradation (acceptable if non-destructive)

**What We Don't Do**:
- ❌ Denial of service (no flooding)
- ❌ Resource exhaustion (no infinite loops)
- ❌ Brute force (limited attempts per credential)

**Recommendation**: Run during maintenance windows or off-peak hours.

---

### 4.3 False Positives & False Negatives

**False Positives** (We report issues that aren't real):
- Occur when: Target behaves unexpectedly
- Example: Endpoint returns "error" message containing "SQL", gets flagged as SQLi
- Mitigation: Use tool agreement (require 2+ tools to confirm)
- Typical rate: 5-15% of findings (depends on target)

**False Negatives** (We miss real issues):
- Occur when: Tools' payloads don't cover specific vulnerability
- Example: Custom authentication scheme not recognized
- Mitigation: Manual testing, tool customization
- Typical rate: 10-20% (especially for logic/config flaws)

**Recommendation**: Use as part of holistic testing, not sole assessment method.

---

### 4.4 Dynamic Content & SPAs

**Limited Coverage**:
- Single-page applications require JavaScript execution
- Our crawler handles basic SPAs, but not all
- Dynamic content revealed only after interaction
- Client-side validation easy to bypass, but server-side may hide issues

**Workaround**:
- Use parameter spider (discovers parameters from external sources)
- Provide seed URLs (known endpoints to start from)
- Use authenticated scanning (more endpoints discovered if logged in)

---

## Part 5: Legal & Compliance

### 5.1 Authorization

**You Must Ensure**:
1. You have authorization to test this target
2. Target owner is aware and approves
3. Testing scope is agreed upon in writing
4. No unauthorized testing of third-party systems

**We Assume**:
- You've obtained necessary permissions
- Target is in scope
- Testing is legally authorized

**We Don't**:
- Verify authorization on your behalf
- Contact targets to request permission
- Assume implied consent

---

### 5.2 Data Handling

**You're Responsible For**:
- Storing scan results securely
- Protecting sensitive data discovered during testing
- Complying with regulations (GDPR, HIPAA, etc.)
- Not sharing findings with unauthorized parties

**We Provide**:
- Encrypted storage options (recommended)
- Export formats for compliance tools
- Clean API results (no raw data dumping)

---

### 5.3 Responsible Disclosure

**Best Practice**:
1. Run scan (findings only visible to your team)
2. Verify findings
3. Report to target owner (if external target)
4. Provide remediation timeline
5. Do not publicly disclose without permission

**Not Our Job**:
- Notify the internet of vulnerabilities
- Publish CVEs
- Share findings in public forums
- Pressure for quick remediation

---

## Part 6: Support & Limitations

### 6.1 What Gets Support

**Supported Configurations**:
- ✅ Linux, macOS, Windows (Python 3.9+)
- ✅ HTTP/1.1, HTTP/2
- ✅ Common web applications (REST APIs, traditional web apps)
- ✅ Standard authentication (Basic, Bearer, API keys, Sessions)
- ✅ Common tools (nuclei, sqlmap, dalfox, etc.)

**Supported Targets**:
- ✅ Public web applications
- ✅ Internal web applications (with access)
- ✅ APIs (REST, GraphQL, SOAP)
- ✅ Web services (typical architecture)

---

### 6.2 What Doesn't Get Support

**Unsupported**:
- ❌ Embedded systems (IoT devices)
- ❌ Mobile applications (native apps require different tools)
- ❌ Desktop applications
- ❌ Proprietary protocols (non-HTTP)
- ❌ Obscure legacy systems

**Why**: Out of scope for HTTP-based vulnerability scanning.

---

## Part 7: Exit Codes & Severity Mapping

### 7.1 CI/CD Exit Codes

```
0 → SUCCESS (No findings)
1 → LOW_ISSUES (Low/Info only)
2 → MEDIUM_ISSUES (Medium or above)
3 → HIGH_ISSUES (High or above)
4 → CRITICAL_ISSUES (Critical present)
5 → ERROR (Scan failed, engine error)
```

### 7.2 Severity Levels

| Level | CVSS | Action |
|-------|------|--------|
| CRITICAL | 9.0-10.0 | Fix immediately |
| HIGH | 7.0-8.9 | Fix in sprint |
| MEDIUM | 4.0-6.9 | Fix in iteration |
| LOW | 0.1-3.9 | Backlog item |
| INFO | 0.0 | Document only |

---

## Part 8: Success Criteria

### 8.1 You Know Phase 4 is Working When:

1. **Determinism**: Run same scan twice, get identical findings (for same target state)
2. **Explainability**: Every finding traces back to source tool and payload
3. **Never Hangs**: Scans complete in expected time, timeouts are explicit
4. **Resumes**: Kill a scan, restart from checkpoint, continue smoothly
5. **Partial Failures**: One tool crashes, others complete, report reflects partial results
6. **CI/CD Integration**: Exit codes work, SARIF/JUnit exports to pipelines
7. **Audit Trail**: Full HTTP history available, reproducible results
8. **Business Context**: Risk scores calculated, OWASP mapped, trends tracked

---

## Part 9: Roadmap & Future

### Planned (Phase 5+)

- Mobile application scanning
- Advanced exploit validation
- Complex business logic detection
- Custom tool integration
- Enterprise SSO integration
- Compliance automation (PCI-DSS, HIPAA)

### Not Planned

- Vulnerability weaponization
- Advanced evasion techniques
- Unauthorized testing support
- Export to attack platforms

---

## Part 10: Contact & Support

### Getting Help

- **Bug reports**: File with reproduction steps
- **Feature requests**: Describe use case and benefit
- **Integration questions**: Describe target system
- **Legal questions**: Consult your legal team (we can't give legal advice)

### Community

- Documentation: In repository
- Examples: Working code samples provided
- Testing: Comprehensive test suite included
- Feedback: Issues and discussions welcome

---

## Signature

**Approved By**: Platform Engineering  
**Date**: 2026-01-12  
**Version**: 4.0.0  
**Status**: Production Ready  

### Single Promise Reminder

> Your scan results are **deterministic, explainable, and auditable**.
> 
> - Run the same scan twice → Get the same results
> - Every finding → Traceable to source
> - Scans → Always finish or resume cleanly

---

**End of Contracts Document**
