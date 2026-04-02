# Quick Integration Guide: Phase 5 Exploitation Framework

## How the System Works Now

### Old Flow (Detection Only)
```
Tools Run → Parse Findings → Report "Possible XSS found"
```

### New Flow (Detection + Active Validation)
```
Tools Run → Crawler → Active Exploitation → Response Analysis → Report "SSRF Confirmed"
                                           ↓
                                      OOB Callbacks
                                           ↓
                                      Error Signatures
```

---

## Key Components

### 1. **Response Diffing Engine** - Proves vulnerability via response variance
- Establishes baseline (no payload)
- Sends payload
- Compares: status code, content length, body similarity, errors, timing
- Confidence score 0.0-1.0

### 2. **OOB Callback System** - Proves blind vulnerabilities
- HTTP server listens for callback indicators
- Generates unique callback URLs per payload
- Detects blind SSRF, XXE, RCE
- Non-blocking threading

### 3. **SSRF Engine** - Detects internal network access
- Metadata probing (AWS, GCP, Azure)
- Internal IP scanning
- File read attempts
- OOB callback integration
- Proof: Response contains metadata OR callback received

### 4. **XSS Engine** - Detects code injection
- Context-aware (HTML, attribute, JavaScript, URL)
- Filter bypasses (encoding, case variation)
- Reflection detection
- Proof: Payload reflected in response

### 5. **SQLi Engine** - Detects SQL injection
- Error-based (error messages in response)
- Boolean-based (true/false response comparison)
- Time-based (response delays)
- Proof: Error signature OR timing delay OR response diff

### 6. **Adaptive Fuzzing** - Retries with mutations
- URL encoding, double encoding
- HTML encoding, Base64, Hex
- Case variation, SQL comments
- 10+ variations per payload

### 7. **Service Fingerprinting** - Identifies services
- Banner grabbing
- HTTP headers
- SSL/TLS analysis
- Version extraction
- Covers Apache, Nginx, IIS, PHP, MySQL, etc.

### 8. **Subdomain Prioritization** - Ranks attack surface
- Classifies (admin, API, CDN, etc.)
- Exposure level assessment
- Priority scoring (0-100)
- Critical target identification

### 9. **Proof-Based Reporter** - Reports only confirmed findings
- Confidence minimum: 0.70 (70%)
- Proof methods documented (callback, diff, error, reflection, timing)
- Rejection of low-confidence findings
- Auto-generated reproduction steps

---

## How to Run

### Automatic (Full Scan)
```bash
python automation_scanner_v2.py example.com
```

The system automatically:
1. Runs discovery tools
2. Crawls endpoints
3. **Initializes exploitation engines** (NEW)
4. **Tests for SSRF, XSS, SQLi** (NEW)
5. **Waits for OOB callbacks** (NEW)
6. **Generates proof-based report** (NEW)

### Manual (Direct Exploitation)
```python
from ssrf_exploitation_engine import SSRFExploitationEngine
from response_diffing_engine import ResponseDiffingEngine
from proof_based_reporter import ProofBasedReporter

# Setup
diffing = ResponseDiffingEngine()
ssrf = SSRFExploitationEngine(response_diffing_engine=diffing)
reporter = ProofBasedReporter()

# Test
result = ssrf.exploit_ssrf(
    endpoint="/api/fetch",
    parameter="url",
    base_url="https://target.com"
)

# Report
if result:
    reporter.add_from_exploitation_result(result)
    report = reporter.generate_report()
```

---

## Understanding the Reports

### Old Report (Detection Only)
```
[MEDIUM] Possible XSS
Endpoint: /search?q=...
Found by: nikto
Confidence: 45%
```

### New Report (Proof-Based)
```
[HIGH] XSS Confirmed
Endpoint: /search
Parameter: q
Payload: <img src=x onerror=alert(1)>
Proof Method: Reflection
  Payload found unescaped in response body
  Status: 200 OK
  Response contains: <img src=x onerror=alert(1)>
Confidence: 0.95 (95%)
Reproduction:
  1. Visit https://target.com/search?q=<img src=x onerror=alert(1)>
  2. Browser console shows: alert executed
  3. Vulnerability confirmed
Remediation: Implement output encoding, use Content-Security-Policy
```

---

## Confidence Scoring Rules

### How Confidence is Calculated

**For SSRF:**
- Metadata in response: 0.95
- Error-based indicators: 0.70
- OOB callback: 0.95
- Port scan response change: 0.50

**For XSS:**
- Unescaped reflection: 0.95
- HTML-encoded reflection: 0.80
- URL-encoded reflection: 0.75
- Context match: 0.65

**For SQLi:**
- SQL error in response: 0.85
- Boolean false/true differ: 0.75
- Time delay >3 seconds: 0.80
- Request timeout: 0.70

### Reporting Threshold
**Only report if confidence ≥ 0.70**

Anything below 0.70 is rejected as "low_confidence"

---

## File Locations

### New Modules (Phase 5)
```
├── response_diffing_engine.py        (Response comparison)
├── oob_callback_system.py             (Blind vuln detection)
├── ssrf_exploitation_engine.py         (SSRF testing)
├── xss_exploitation_engine.py          (XSS testing)
├── sqli_exploitation_engine.py         (SQLi testing)
├── adaptive_fuzzing_engine.py          (Filter bypass)
├── service_fingerprinting_engine.py    (Service ID)
├── subdomain_prioritization.py         (Attack surface ranking)
├── proof_based_reporter.py             (Confirmed findings)
└── Documentations/
    └── PHASE_5_EXPLOITATION_FRAMEWORK.md  (Full documentation)
```

### Integration Points
```
automation_scanner_v2.py
├── Line 50: New imports added
├── Line 178: Engines initialized in __init__
├── Line 1920: Exploitation phase called after crawler
└── Line 2500+: New methods:
    ├── initialize_exploitation_engines()
    ├── run_active_exploitation()
    ├── prioritize_subdomain_targets()
    └── generate_proof_based_final_report()
```

---

## Debugging & Troubleshooting

### OOB Callback Server Not Starting
```python
# Check if port 8888 is available
import socket
try:
    s = socket.socket()
    s.bind(('127.0.0.1', 8888))
    s.close()
    print("Port 8888 available ✓")
except:
    print("Port 8888 in use - change port in oob_system.py")
```

### Exploitation Taking Too Long
- Default limit: 10 endpoints × 3 parameters = 30 tests
- Each test tries SSRF, XSS, SQLi (3 engines)
- Timeout per test: 10 seconds
- Total max: 300 seconds (5 minutes)
- OOB wait: 5 seconds

### Low Confidence Findings Rejected
- Check `/execution_report.json` → `proof_reporter.rejected_low_confidence`
- Review confidence scoring for your payload
- Try different payload/encoding combinations
- Increase fuzzing attempts

### No OOB Callbacks Detected
- Check external IP: `oob_system.external_ip`
- Verify firewall allows inbound on 8888
- Confirm payload syntax correct (`http://<IP>:8888/<ID>`)
- Check target actually fetches the URL

---

## Performance Optimization

### For Large Targets
```python
scanner = AutomationScannerV2(target="example.com")

# Limit endpoints tested (default: 10)
# In run_active_exploitation(), change:
# for endpoint_obj in endpoints_to_test[:10]:  ← increase this number

# Limit parameters per endpoint (default: 3)
# for param in params[:3]:  ← increase this number

# Reduce OOB wait time (default: 5s)
# time.sleep(5)  ← reduce to 2-3s if needed
```

### Parallelization
The system uses sequential testing to avoid race conditions. For parallelization:
1. Use ThreadPoolExecutor with session clones
2. Ensure OOB callbacks use thread-safe queue
3. Implement per-thread diffing baselines

---

## Extending the Framework

### Add Custom Exploitation Engine
```python
from dataclasses import dataclass
from typing import Dict, Optional

class CustomVulnerabilityEngine:
    """Template for custom exploitation engines"""

    def exploit(self, endpoint: str, parameter: str,
                base_url: str, session=None) -> Optional[Dict]:
        """
        Returns: {
            "type": "Custom Vuln",
            "endpoint": endpoint,
            "parameter": parameter,
            "payload": "...",
            "confidence": 0.85,
            "proof": {"method": "...", "evidence": "..."}
        }
        """
        pass

# Register in automation_scanner_v2.py __init__:
# self.custom_engine = CustomVulnerabilityEngine()

# Call in run_active_exploitation():
# result = self.custom_engine.exploit(endpoint, param, base_url, session)
# if result:
#     self.proof_reporter.add_from_exploitation_result(result)
```

### Add Custom Proof Method
```python
# In proof_based_reporter.py, extend ConfirmationMethod enum:
class ConfirmationMethod(Enum):
    # ...existing...
    CUSTOM_PROOF = "custom_proof"
```

---

## Testing Checklist

- [ ] Run full scan: `python automation_scanner_v2.py example.com`
- [ ] Check `/execution_report.json` contains exploitation results
- [ ] Verify OOB server started: Check logs for port 8888
- [ ] Review `/security_report.html` shows confirmed findings (no "possible")
- [ ] Check `/findings_summary.txt` contains reproduction steps
- [ ] Validate confidence scores ≥0.70 for all reported findings
- [ ] Confirm rejected_low_confidence count if any
- [ ] Verify service fingerprinting output in report
- [ ] Check subdomain prioritization results

---

## FAQ

**Q: Why is a finding marked as "Low Confidence"?**
A: Confidence < 0.70 (70%). Check `execution_report.json` → `proof_reporter.rejected_low_confidence` for your finding.

**Q: Why no OOB callbacks detected?**
A: 1) Firewall blocks port 8888, 2) Payload syntax wrong, 3) Target doesn't execute payload, 4) Wait time too short.

**Q: Can I skip exploitation and run detection only?**
A: Yes, comment out `initialize_exploitation_engines()` and `run_active_exploitation()` calls in `run_full_scan()`.

**Q: How do I report false positives?**
A: Check `response_diffing_engine.py` → `_analyze_ssrf_response()` or similar. Adjust confidence thresholds.

**Q: How do I add custom payloads?**
A: Extend payload lists in SSRF/XSS/SQLi engine classes. Regenerate mutation sequence via `AdaptiveFuzzingEngine.generate_mutations()`.

---

## Command Reference

```bash
# Full scan with exploitation
python automation_scanner_v2.py example.com

# With custom output directory
python automation_scanner_v2.py example.com -o ./my_results

# Skip tool verification (faster)
python automation_scanner_v2.py example.com --skip-tool-check

# Direct module import
python -c "from ssrf_exploitation_engine import SSRFExploitationEngine; print('✓ Import OK')"
```

---

## Support & Documentation

**Framework Documentation:**
→ `Documentations/PHASE_5_EXPLOITATION_FRAMEWORK.md`

**Source Code Comments:**
All new modules include inline documentation via docstrings.

**Logging:**
Enable `logging.DEBUG` for detailed execution trace:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

**Version:** Phase 5 - Active Exploitation
**Status:** Ready for integration testing
**Last Updated:** March 23, 2026
