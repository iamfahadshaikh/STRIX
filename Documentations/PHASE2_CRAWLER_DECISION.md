# Phase 2 Decision: Crawler Selection Framework

## Context

You need **one** crawler to unlock the application layer.
This document helps you choose wisely.

---

## The Three Options

### Option A: Katana (Recommended)

**What it is:**
```
Modern web crawler built by ProjectDiscovery
Written in Go
JS-aware
Fast
Output: JSON (URLs, methods, params)
```

**Strengths:**
- ✅ **Speed:** 100+ URLs/second
- ✅ **JS Support:** Executes JavaScript
- ✅ **Format:** Clean JSON output
- ✅ **Modern:** Active development
- ✅ **Deployable:** Single binary (no runtime deps)
- ✅ **Integrated:** You already use projectdiscovery tools

**Weaknesses:**
- ❌ **Timeout Risk:** Can hang on bad servers
- ❌ **Auth Handling:** Limited (basic only)
- ❌ **Coverage:** Misses some edge cases

**Installation:**
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

**Usage:**
```bash
katana -u https://target.com \
  -js-crawl \
  -depth 2 \
  -json \
  -o crawl.json
```

**Integration Effort:** Low (2-3 days)

**Output Example:**
```json
{
  "request": {
    "url": "https://target.com/api/users",
    "method": "POST"
  },
  "body": "id=1&name=test",
  "headers": {...}
}
```

---

### Option B: OWASP ZAP (Headless)

**What it is:**
```
Industry-standard penetration testing tool
Headless mode available
Mature ecosystem
Output: JSON / XML
```

**Strengths:**
- ✅ **Industry Standard:** Known and trusted
- ✅ **Mature:** 10+ years of development
- ✅ **Extensible:** Plugin ecosystem
- ✅ **Reporting:** Built-in HTML/PDF export
- ✅ **Community:** Large, well-documented

**Weaknesses:**
- ❌ **Slow:** Slower than Katana (30-100 URLs/sec)
- ❌ **Heavy:** Requires Java + RAM
- ❌ **Setup:** More complex configuration
- ❌ **Overkill:** Too many features you don't need

**Installation:**
```bash
sudo apt install zaproxy
```

**Usage:**
```bash
zaproxy \
  -cmd \
  -quickurl https://target.com \
  -quickout report.json \
  -config api.disablekey=true
```

**Integration Effort:** Medium (3-5 days)

**Output Example:**
```xml
<scan>
  <item>
    <url>https://target.com/api/users</url>
    <method>POST</method>
    <param name="id"/>
    <param name="name"/>
  </item>
</scan>
```

---

### Option C: Playwright (Custom)

**What it is:**
```
Browser automation library
Full control
Maximum JS support
Written in Python (matches your stack)
```

**Strengths:**
- ✅ **Control:** Full flexibility
- ✅ **JS Support:** Complete (real Chromium)
- ✅ **Python:** Matches your language
- ✅ **Integrable:** Custom extraction logic
- ✅ **Modern:** Actively maintained

**Weaknesses:**
- ❌ **Slow:** Slowest (10-50 URLs/sec)
- ❌ **Binary:** Requires chromium binary
- ❌ **Complex:** More code to write
- ❌ **Maintenance:** Custom code burden
- ❌ **Flaky:** Playwright often needs debugging

**Installation:**
```bash
pip install playwright
playwright install chromium
```

**Usage:**
```python
from playwright.sync_api import sync_playwright

async def crawl(url):
    async with sync_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto(url)
        links = await page.eval_on_selector_all('a', 'el => el.href')
        await browser.close()
        return links
```

**Integration Effort:** High (5-7 days)

**Output:** Custom JSON structure

---

## Decision Matrix

| Criterion | Katana | ZAP | Playwright |
|-----------|--------|-----|-----------|
| Speed | 🟢 Fast | 🟡 Medium | 🔴 Slow |
| Setup | 🟢 Easy | 🟡 Medium | 🟡 Medium |
| JS Support | 🟢 Good | 🟡 Basic | 🟢 Excellent |
| Integration | 🟢 Easy | 🟡 Medium | 🔴 Hard |
| Maintenance | 🟢 Low | 🟡 Medium | 🔴 High |
| Timeout Handling | 🟡 Fair | 🟢 Good | 🟢 Good |
| Output Format | 🟢 Clean | 🟡 Verbose | Custom |
| Reliability | 🟢 Stable | 🟢 Stable | 🟡 Flaky |

---

## Recommendation: **Katana**

**Why:**

1. **Speed:** You need crawling that doesn't block the scanner (15s timeout)
   - Katana: ✅ Can finish in 5-10s
   - ZAP: ⚠️ Might timeout
   - Playwright: ❌ Will timeout

2. **Ecosystem:** You already use projectdiscovery tools
   - nuclei ✅
   - subfinder ✅
   - httpx ✅
   - Katana fits the pattern

3. **Output:** Clean JSON that's easy to parse
   - Katana: ✅ Simple structure
   - ZAP: ⚠️ Verbose XML
   - Playwright: 🟡 Custom parsing needed

4. **Integration:** Minimal code, minimal risk
   - Katana: ✅ 2-3 days
   - ZAP: 3-5 days
   - Playwright: 5-7 days

5. **Modern:** Actively maintained for web security
   - Katana: ✅ Latest web attack vectors
   - ZAP: ✅ Mature but slower updates
   - Playwright: ✅ General-purpose, overkill

---

## Implementation Plan: Katana

### Step 1: Install & Test Standalone (2h)

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Test on known target
katana -u https://example.com -json -o /tmp/test.json

# Check output
cat /tmp/test.json | jq . | head -20
```

### Step 2: Parse Katana Output (4h)

```python
import json
import subprocess

def run_katana(url, timeout=10):
    try:
        result = subprocess.run(
            ['katana', '-u', url, '-json', '-depth', '2'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            crawl_results = [json.loads(line) for line in lines if line]
            return extract_endpoints(crawl_results)
        return None
    except subprocess.TimeoutExpired:
        return None

def extract_endpoints(crawl_results):
    endpoints = {}
    for item in crawl_results:
        req = item.get('request', {})
        url = req.get('url', '')
        method = req.get('method', 'GET')
        body = req.get('body', '')

        endpoints[url] = {
            'method': method,
            'parameters': extract_params_from_body(body),
            'forms': []  # TODO: extract forms
        }
    return endpoints

def extract_params_from_body(body):
    # Parse URL-encoded params
    if not body:
        return []
    params = []
    for pair in body.split('&'):
        if '=' in pair:
            key, _ = pair.split('=', 1)
            params.append(key)
    return params
```

### Step 3: Integrate into DiscoveryCache (4h)

```python
# In automation_scanner_v2.py

def _run_crawl_phase(self):
    """New phase: crawling"""
    if self.profile.type.name == "ROOT_DOMAIN":
        return None  # Skip for root domains (too slow)

    url = f"{'https' if self.profile.is_https else 'http'}://{self.profile.host}"

    try:
        endpoints = run_katana(url, timeout=10)
        if endpoints:
            self.cache.add_crawl_results(endpoints)
            return endpoints
    except Exception as e:
        self.log(f"Crawl failed: {e}", "WARNING")

    return None
```

### Step 4: Gate Payload Tools (2h)

```python
# In execution loop

if gating_orchestrator and tool_name in ["dalfox", "sqlmap"]:
    crawl_endpoints = self.cache.get_crawl_endpoints()

    if tool_name == "dalfox" and not crawl_endpoints.get("reflected"):
        self.log(f"[dalfox] Gated (no reflection endpoints)", "INFO")
        continue

    if tool_name == "sqlmap" and not crawl_endpoints.get("params"):
        self.log(f"[sqlmap] Gated (no parameters)", "INFO")
        continue
```

### Step 5: Test End-to-End (2h)

```bash
# Test on subdomain (crawling enabled)
python3 automation_scanner_v2.py api.example.com

# Watch for:
# [INFO] Running crawling phase...
# [SUCCESS] Crawling complete: 10 endpoints, 3 parameters
# [INFO] [dalfox] Running on 2 reflection endpoints
# [INFO] [sqlmap] Running on 3 parameter endpoints
```

---

## Fallback Plan (If Katana Hangs)

Add aggressive timeout handling:

```python
def run_katana_safe(url, timeout=10):
    process = subprocess.Popen(
        ['katana', '-u', url, '-json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        stdout, _ = process.communicate(timeout=timeout)
        return parse_katana_output(stdout)
    except subprocess.TimeoutExpired:
        process.kill()
        return None  # Crawl failed, continue without it
```

---

## Migration Path (If You Change Your Mind)

If Katana doesn't work:
1. **Try ZAP** (2-3 days additional work)
2. **Fall back to Playwright** (another 2-3 days)

But you won't need to. Katana is the right choice.

---

## Decision Point

**Do you want to proceed with Katana?**

If yes:
1. Approve this plan
2. Start with Step 1 (install + test)
3. Report back on output format
4. I'll help with Steps 2-5

If you want to explore ZAP or Playwright first:
1. Let me know
2. I'll prep detailed plan for that

But my recommendation stands: **Katana**.
