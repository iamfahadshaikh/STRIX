# Crawler Integration Guide

**Status**: New capability (Stateful crawling layer)  
**Added**: January 2026  
**Purpose**: Discover endpoints, parameters, forms → gate payload tools  
**Constraint**: No modifications to core automation_scanner_v2.py (yet)

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  automation_scanner_v2.py (FROZEN)              │
│  - Orchestrates tools via decision_ledger       │
└────────────┬────────────────────────────────────┘
             │
             ├─► [1-8] DNS, Network, Web tools (existing)
             │
             └─► [NEW] Crawl integration layer
                 ↓
         ┌──────────────────────────────┐
         │ crawler_integration.run()     │
         ├──────────────────────────────┤
         │ 1. Check if crawl needed     │
         │ 2. Execute Katana           │
         │ 3. Parse results            │
         │ 4. Feed cache               │
         │ 5. Return gating signals    │
         └──────────────────────────────┘
                 ↓
         ┌──────────────────────────────┐
         │ decision_ledger              │ (future mod)
         ├──────────────────────────────┤
         │ Gate based on:               │
         │ - has_parameters?            │
         │ - has_reflections?           │
         │ - has_forms?                 │
         │ - has_api?                   │
         └──────────────────────────────┘
                 ↓
         ┌──────────────────────────────┐
         │ Payload tools (conditional)  │
         │ - xsstrike (if reflections)  │
         │ - sqlmap (if params)         │
         │ - commix (if params)         │
         │ - dalfox (if reflections)    │
         └──────────────────────────────┘
```

---

## New Modules

### 1. `katana_crawler.py` - Full-Featured Crawler

**Purpose**: Execute Katana, handle timeouts, parse output

**Key Class**: `KatanaCrawler`

```python
from katana_crawler import KatanaCrawler

crawler = KatanaCrawler(
    target="https://example.com",
    depth=2,
    timeout=180,
    js_crawl=True
)

if crawler.is_available():
    if crawler.crawl():
        # Get results
        summary = crawler.get_summary()
        endpoints = crawler.get_endpoints()
        params = crawler.get_unique_parameters()
```

**Pros**: Full JS rendering, comprehensive crawl  
**Cons**: Requires Go + Katana install, slower (30+ seconds)

---

### 2. `light_crawler.py` - Fast HTTP-Based Crawler (NEW)

**Purpose**: Quick endpoint discovery without browser automation

**Key Class**: `LightCrawler`

```python
from light_crawler import LightCrawler

crawler = LightCrawler(
    target="https://example.com",
    timeout=30,
    max_pages=50
)

if crawler.crawl():
    summary = crawler.get_summary()
    # Returns same format as KatanaCrawler for compatibility
```

**Pros**: No external dependencies, fast (~1-2 seconds), works immediately  
**Cons**: No JS rendering, regex-based (less accurate but sufficient for gating)

**Test Results** (dev-erp.sisschools.org):
- 20 endpoints discovered
- 5 parameters extracted
- 2 reflectable parameters identified
- Runtime: ~2 seconds

---

### 3. `crawl_parser.py` - Output Parser

**Output Format**:
```json
{
  "summary": {
    "target": "https://example.com",
    "endpoints": 42,
    "unique_parameters": 15,
    "forms": 3,
    "api_endpoints": 5,
    "crawled_urls": 128,
    "parameters": {
      "search": ["value1"],
      "id": ["123", "456"],
      "redirect": ["http://example.com"]
    },
    "endpoints_list": ["https://example.com/page1", ...],
    "forms_list": [{"action": "/login", "fields": [...]}]
  },
  "results": [
    {
      "url": "https://example.com/page1",
      "status_code": 200,
      "method": "GET",
      "params": {"q": ["test"]},
      "is_api": false,
      "tags": ["crawled", "web", "status_200"]
    }
  ]
}
```

---

### 2. `crawl_parser.py` - Output Parser

**Purpose**: Convert Katana JSON to cache_discovery format + gating signals

**Key Class**: `CrawlParser`

```python
from crawl_parser import CrawlParser

# Parse raw Katana output
result = CrawlParser.parse_katana_results(katana_json)
# Returns: {endpoints, parameters, forms, api_endpoints, reflections, total_crawled}

# Convert to cache format
cache_format = CrawlParser.to_cache_format(result)

# Extract gating signals for payload tools
gating = CrawlParser.extract_for_payload_gating(result)
# Returns:
# {
#   "has_parameters": True,
#   "parameter_count": 15,
#   "parameter_names": ["search", "id", ...],
#   "has_forms": True,
#   "form_count": 3,
#   "has_api": True,
#   "api_count": 5,
#   "reflectable_params": ["search", "id", "redirect"],
#   "reflection_count": 3,
#   "crawled_url_count": 128
# }
```

**Reflection Detection**:
Automatically identifies potentially reflectable parameters:
- `search, q, query, text, message, comment`
- `id, uid, user_id, post_id`
- `redirect, callback, return, url`
- `file, path, filename`
- Patterns: `*_id`, `*_name`, `*_param`, `*_query`

---

### 4. `crawler_integration.py` - Hybrid Integration Layer (UPDATED)

**Purpose**: Orchestrate crawl execution with automatic fallback

**Key Class**: `CrawlerIntegration`

**Strategy** (NEW):
1. Try Katana if available (full-featured)
2. Automatically fall back to light_crawler (fast)
3. Return standardized gating signals

```python
from crawler_integration import CrawlerIntegration

crawler_int = CrawlerIntegration(
    target="https://example.com",
    cache=cache_discovery,
    output_dir="./scan_results/",
    timeout=180,
    depth=2
)

# Run (tries Katana, falls back to light_crawler automatically)
success, gating_signals = crawler_int.run()

if success:
    # gating_signals includes:
    # - crawler_type: "katana" or "light"
    # - parameter_count, reflection_count, form_count
    # - Tool-specific gating decisions
    
    should_xss = crawler_int.get_gating_decision("xsstrike")
    should_sql = crawler_int.get_gating_decision("sqlmap")
```

**Gating Rules** (unified across both crawlers):

| Tool | Gate Rule |
|------|-----------|
| xsstrike | `reflection_count > 0` OR `has_forms` |
| dalfox | `reflection_count > 0` |
| sqlmap | `parameter_count > 0` |
| commix | `parameter_count > 0` |
| nuclei | Always (different model) |

---

### 3. `crawl_parser.py` - Output Parser

To fully integrate into automation_scanner_v2.py, these changes are needed:

### Option A: Minimal (add after DNS/Network phase)

```python
# In automation_scanner_v2.py, after nmap runs:

from crawler_integration import CrawlerIntegration

if self.target_profile.is_web():
    crawler_int = CrawlerIntegration(
        target=self.target,
        cache=self.cache_discovery,
        output_dir=self.output_dir,
        timeout=300,
        depth=2
    )
    success, gating_signals = crawler_int.run()
    
    # Store gating signals
    self.crawl_gating = gating_signals
```

Then in decision_ledger:
```python
def should_run_xsstrike(self) -> bool:
    # Gate on crawl signals
    if hasattr(self, 'crawl_gating'):
        return self.crawl_gating['reflection_count'] > 0
    return False  # Conservative if no crawl data
```

### Option B: Full (modify decision_ledger)

```python
# In decision_ledger.py:

class DecisionLedger:
    def __init__(self, ...):
        # ... existing code
        self.crawler_integration = None
        self.crawl_gating = None
    
    def gate_on_crawl_results(self, crawler_int):
        """Update allow/block based on crawl signals"""
        success, gating = crawler_int.run()
        self.crawl_gating = gating
        
        # Conditional rules
        if gating['reflection_count'] > 0:
            self.ALLOW['xsstrike'] = True
            self.ALLOW['dalfox'] = True
        else:
            self.BLOCK['xsstrike'] = "No reflectable params found"
            self.BLOCK['dalfox'] = "No reflectable params found"
        
        if gating['parameter_count'] > 0:
            self.ALLOW['sqlmap'] = True
            self.ALLOW['commix'] = True
        else:
            self.BLOCK['sqlmap'] = "No parameters found"
            self.BLOCK['commix'] = "No parameters found"
```

---

## Installation

### Katana (Required for Crawling)

```bash
# Install Go (if not already installed)
# https://golang.org/doc/install

# Install Katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Verify
katana -version
```

---

## Standalone Testing

Test crawler without modifying core scanner:

```bash
# Test crawl
python3 katana_crawler.py https://dev-erp.sisschools.org

# Parse output
python3 -c "
from katana_crawler import KatanaCrawler
from crawl_parser import CrawlParser
import json

crawler = KatanaCrawler('https://example.com', depth=1, timeout=60)
if crawler.crawl():
    result = CrawlParser.parse_katana_results(crawler.to_json())
    print(json.dumps(result, indent=2))
"
```

---

## Future Enhancements

1. **Cache Integration** - Wire into cache_discovery.add_*() methods
2. **Decision Layer** - Formalize in decision_ledger.py
3. **Parallel Crawling** - Run multiple crawl strategies in parallel
4. **JavaScript Analysis** - Extract security-relevant JS patterns
5. **API Detection** - Automatic Swagger/GraphQL detection
6. **Confidence Scoring** - Mark findings from crawl sources with confidence

---

## Current State

✅ Crawler wrapper (katana_crawler.py) - Fully functional  
✅ Light crawler (light_crawler.py) - Fully functional (NEW)  
✅ Parser (crawl_parser.py) - Reflection detection, gating signals  
✅ Integration layer (crawler_integration.py) - Hybrid orchestration with fallback  
✅ Tested on real target (dev-erp.sisschools.org) - 20 endpoints, 5 params discovered  
❌ Wired into automation_scanner_v2.py - Pending (no core code mod yet)  
❌ Decision ledger gating - Documented, not implemented  

**Next**: Decide on integration approach (Option A vs B) or run standalone tests
