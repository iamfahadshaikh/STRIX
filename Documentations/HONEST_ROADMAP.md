# VAPT Engine - Honest Roadmap & Current State Assessment

## Executive Summary

**Right now:** High-quality recon + controlled attack framework
**Missing:** Stateful application visibility (crawler)
**Next critical move:** Integrate stateful crawling into discovery pipeline

---

## Current State (Honest Truth)

### ✅ What Works Well

| Component | Status | Quality |
|-----------|--------|---------|
| Architecture | Solid | Better than many commercial tools |
| Signal-driven gating | Working | xsstrike/dalfox/sqlmap correctly gated |
| Discovery cache | Working | Single source of truth for recon data |
| DNS reconnaissance | Complete | dig_*, dnsrecon |
| Subdomain enumeration | Complete | findomain, sublist3r, assetfinder |
| Network scanning | Complete | nmap_quick, nmap_vuln |
| Web fingerprinting | Good | whatweb working |
| Misconfig detection | Good | nikto, sslscan, testssl |
| Runtime budgeting | Working | 30m timeout enforced |
| HTTPS probing | Fixed | Reliable scheme detection |

### ❌ What's Missing

| Component | Impact | Why Matters |
|-----------|--------|------------|
| **Stateful crawling** | 🔴 CRITICAL | Can't execute JS, follow links, extract forms |
| **Real endpoint mapping** | 🔴 CRITICAL | Payload tools have no real targets |
| **Parameter discovery** | 🔴 CRITICAL | Dalfox/sqlmap/commix mostly fire blank |
| **Session handling** | 🟡 Important | No authenticated scanning |
| **API discovery** | 🟡 Important | OpenAPI/GraphQL endpoints invisible |
| **JS execution** | 🟡 Important | Modern apps unreachable |
| **Favicon hash** | 🟡 Important | Tech detection incomplete |
| **OWASP confidence** | 🟡 Important | Results feel hollow without scoring |

---

## Why It Feels Small

```
Current Pipeline:
┌─────────────────────────────────────────────┐
│ Discovery (DNS, subdomains, network)        │
│         ↓                                   │
│ Lightweight expansion (HTTP fingerprint)    │
│         ↓                                   │
│ Payload tools (dalfox/sqlmap) [fire blank] │
│         ↓                                   │
│ Report                                      │
└─────────────────────────────────────────────┘

Reality:
The engine cannot "SEE" the application because:
• No JS execution
• No form traversal
• No stateful crawling
• No parameter extraction

Result:
• Dalfox finds no reflection endpoints
• Sqlmap finds no injection points
• Coverage is ~15-20% of real attack surface
```

---

## Reference Pipeline (Professional Scanners)

```
Discovery (passive recon)
    ↓
[MISSING: STATEFUL CRAWLING] ← YOUR BLOCKER
    ↓
Endpoint Graph + Parameter Mapping
    ↓
Payload Testing (guided by crawler signals)
    ↓
Correlation + Confidence Scoring
    ↓
OWASP Assessment
```

---

## Roadmap: Phases (Not Chaos)

### Phase 1: Extended Recon (1-2 weeks, low risk)

**Add without modifying core architecture:**

```python
# httpx - HTTP service verification
httpx -u targets.txt -status-code -title -json

# masscan - Fast port discovery (UDP/ICMP)
masscan -p1-65535 --rate=10000

# waybackurls + gau - Historical endpoints
waybackurls domain.com | gau domain.com

# arjun - Parameter discovery (bruteforce)
arjun -u http://target.com

# wappalyzer / builtwith - Better tech mapping
wappalyzer scan http://target.com
```

**Impact:**
- Much richer DiscoveryCache
- Better gating signals for payload tools
- Still stateless and safe

---

### Phase 2: Stateful Crawling (2-3 weeks, CRITICAL BLOCKER)

**Choose ONE first (not all):**

#### Option A: Katana (Recommended)
```bash
katana -u https://target.com -js-crawl -depth 2
Output: URLs, methods, parameters, forms
```

Pros:
- Fast
- Modern
- JS-aware
- Output to JSON

Cons:
- Timeout risk (you already handle this)

#### Option B: OWASP ZAP (Headless)
```bash
zaproxy -cmd -quickurl https://target.com -quickout report.json
```

Pros:
- Industry standard
- More mature
- Headless mode

Cons:
- Heavier
- Slower

#### Option C: Playwright (Later)
```python
async def crawl_with_playwright(url):
    browser = await chromium.launch()
    page = await browser.new_page()
    await page.goto(url)
    # Extract forms, params
```

Pros:
- Full control
- Maximum JS support

Cons:
- Requires browser binary
- Slow
- Complex

**Action:** Start with Katana, integrate into DiscoveryCache.

**Output structure:**
```json
{
  "crawl_endpoints": [
    {
      "url": "https://target.com/api/users",
      "method": "POST",
      "parameters": ["id", "name", "email"],
      "forms": [{"name": "login_form", "fields": ["user", "pass"]}],
      "reflections": ["name", "email"]
    }
  ]
}
```

---

### Phase 3: Payload Engine Integration (1 week)

**Wire crawler output → tool gating**

**Current (blind):**
```python
# Dalfox runs on everything
dalfox file all_urls.txt
```

**After crawling (targeted):**
```python
reflection_endpoints = [url for url in crawl if url.reflections]
dalfox file reflection_endpoints.txt  # Only runs on URLs with reflections
```

**Same for sqlmap/commix:**
```python
param_endpoints = [url for url in crawl if url.parameters]
sqlmap -m param_endpoints.txt --batch
```

**Result:**
- Payload tools run on real targets, not noise
- Finding signal dramatically improves
- No more blank fires

---

### Phase 4: OWASP + Confidence Scoring (1-2 weeks)

**Map discoveries to OWASP Top 10:**

```python
mapping = {
    FindingType.XSS: OWASP.A07_2021_CROSS_SITE_SCRIPTING,
    FindingType.SQL_INJECTION: OWASP.A03_2021_INJECTION,
    FindingType.WEAK_CRYPTO: OWASP.A02_2021_CRYPTOGRAPHIC_FAILURES,
}
```

**Score by confidence:**

```python
confidence = 0.0

# Tool agreement
if dalfox.confirmed and xsstrike.confirmed:
    confidence += 0.4
elif dalfox.confirmed or xsstrike.confirmed:
    confidence += 0.2

# Payload success
if tool_output.matched_payload:
    confidence += 0.3

# Signal strength
if signal.is_reflected_verbatim:
    confidence += 0.3
```

**Result:**
- Findings rank by credibility
- OWASP categories clear
- Assessments feel professional

---

### Phase 5: Advanced (Backlog, Optional)

- Authenticated crawling (cookies, OAuth)
- API testing (OpenAPI, GraphQL discovery)
- Traffic replay (Burp log import)
- CI/CD mode (fast regression scans)
- Custom exploit chains

---

## What's Already Done (Leverage It)

✅ **Architecture** - no rewrite needed
✅ **Gating logic** - dalfox/sqlmap gates work
✅ **DiscoveryCache** - ready for crawler output
✅ **OWASP mapping** - infrastructure there
✅ **Reports** - structure handles findings
✅ **Runtime budgeting** - won't break on slow crawlers

---

## Cleanup & Documentation (Parallel)

### Code
- [ ] Remove dead tool definitions
- [ ] Centralize tool metadata (timeouts, OWASP category, signals)
- [ ] Freeze public APIs (profile, cache, findings)
- [ ] Document integration points for new tools

### Docs
- [ ] Create `WHAT_THIS_IS.md` (recon framework, not full vuln scanner)
- [ ] Create `ROADMAP.md` (phases above)
- [ ] Create `TOOL_SELECTION_RATIONALE.md` (why each tool, not random)
- [ ] Update `ENGINE_GUARANTEES.md` (what crawler changes)

---

## Critical Insight: Crawling is the Blocker

**Everything else you need already exists:**
- Dalfox (XSS) ✅
- Sqlmap (SQLi) ✅
- Commix (command injection) ✅
- Nuclei (template matching) ✅

**What's missing:**
- Real endpoints
- Real parameters
- Real attack surface visibility

**One integration solves this:**
> Katana → DiscoveryCache → Payload Tools

---

## Timeline Estimate

| Phase | Effort | Timeline | Risk |
|-------|--------|----------|------|
| Phase 1 (extended recon) | 40h | 1-2 weeks | Low |
| Phase 2 (crawling) | 60h | 2-3 weeks | Medium (timeout handling) |
| Phase 3 (payload wiring) | 20h | 1 week | Low |
| Phase 4 (OWASP/scoring) | 40h | 1-2 weeks | Low |
| **Total** | **160h** | **6-8 weeks** | **Medium** |

---

## Starting Point (Monday Morning Plan)

1. **Read** this roadmap (30 min)
2. **Decide** crawler (Katana vs ZAP) (15 min)
3. **Prototype** katana integration (4h)
   - Run katana on test domain
   - Parse JSON output
   - Insert into DiscoveryCache
4. **Test** payload tools on crawler output (2h)
   - Dalfox with real reflection endpoints
   - Sqlmap with real parameter endpoints
5. **Measure** improvement (1h)
   - Before: X findings, Y noise
   - After: Better signal-to-noise ratio

**That day:** You'll know if this is the right blocker.

---

## Verdict

This isn't a "build 50 random tools" situation.
It's a **"wire one critical piece (crawling) and watch everything click into place"** situation.

Your architecture is ready.
Your tools are ready.
You just need the crawling layer.

That's it.

---

## Questions to Answer Before Starting Phase 2

1. **Katana vs ZAP?** (Recommend Katana for speed)
2. **Crawl depth?** (2-3 levels recommended, configurable)
3. **JS execution timeout?** (15s suggested)
4. **Output format?** (JSON endpoint list, parameters, reflections)
5. **Cache integration?** (Append to DiscoveryCache, don't replace)
6. **Payload gating?** (Reflect endpoints → dalfox, param endpoints → sqlmap)

Once you answer those, Phase 2 is straightforward implementation.
