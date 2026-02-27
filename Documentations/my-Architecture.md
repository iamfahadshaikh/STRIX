            ┌──────────────────────────────────────┐
            │           START SCAN (TARGET)         │
            │ CLI / API invocation                  │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Input Normalization                   │
            │ - strip paths                         │
            │ - resolve scheme                      │
            │ - punycode / IP handling              │
            │ - canonical host                      │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ HTTPS / Reachability Probe            │
            │ - TCP connect                         │
            │ - HTTP vs HTTPS                       │
            │ - redirects                           │
            │ - cached result reuse                 │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Initialize Scan Context               │
            │ - scan_id                             │
            │ - timestamps                          │
            │ - config flags                        │
            │ - tool allowlist                      │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Discovery Cache (Single Truth)        │
            │ - host profile                        │
            │ - signals ledger                      │
            │ - execution ledger                    │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Tool Gating Engine                    │
            │ - prerequisites met?                 │
            │ - protocol allowed?                  │
            │ - already executed?                  │
            │ - dependency signals present?         │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Phase 1: Discovery Execution          │
            │ - DNS / Subdomains                    │
            │ - Port scan                           │
            │ - HTTP headers                        │
            │ - TLS analysis                        │
            │ - Tech fingerprint                   │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Parse Discovery Output                │
            │ - structured parser                  │
            │ - confidence per signal               │
            │ - failures → BLOCKED_PARSE_FAILED     │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Discovery Sufficiency Check           │
            │ DNS + Ports + Web + TLS present?      │
            └───────────────┬───────────────┬──────┘
                            │ NO            │ YES
                            │               ↓
            ┌───────────────▼───────┐   ┌──────────────────────────────────────┐
            │ Mark Coverage Gaps     │   │ Phase 2: Crawler Decision             │
            │ (report-only)          │   │ - HTTP reachable?                     │
            └───────────────────────┘   │ - HTML content?                       │
                                        │ - JS detected?                        │
                                        └───────────────────┬──────────────────┘
                                                            ↓
            ┌──────────────────────────────────────┐
            │ Execute Crawler (MANDATORY)           │
            │ Katana:                               │
            │ - DOM parsing                         │
            │ - JS endpoints                        │
            │ - forms                               │
            │ - XHR / fetch                         │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Endpoint Graph Construction           │
            │ - URL nodes                           │
            │ - param provenance                   │
            │   (FORM / URL / JS / API)             │
            │ - methods                             │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Any Valid Attack Surface?             │
            │ endpoints + params + methods          │
            └───────────────┬───────────────┬──────┘
                            │ NO            │ YES
                            │               ↓
            ┌───────────────▼───────┐   ┌──────────────────────────────────────┐
            │ Payload Phase BLOCKED │   │ Phase 3: Payload Readiness Gate       │
            │ (No crawl surface)    │   │ - param type known?                   │
            │                       │   │ - context (HTML/JS/SQL)?              │
            └───────────────────────┘   │ - method safe?                        │
                                        └───────────────────┬──────────────────┘
                                                            ↓
            ┌──────────────────────────────────────┐
            │ Payload Strategy Builder              │
            │ - baseline payload                    │
            │ - encoding variants                   │
            │ - mutation sets                       │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Tool Command Builder                  │
            │ dalfox / sqlmap / commix              │
            │ ONLY crawler-derived params           │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Execute Payload Tools                 │
            │ - strict target list                  │
            │ - rate limited                        │
            │ - monitored                           │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Payload Result Parsing                │
            │ - exploit evidence                    │
            │ - reflection proof                    │
            │ - DB error / timing                   │
            └───────────────┬───────────────┬──────┘
                            │ NO SIGNAL     │ SIGNAL
                            │               ↓
            ┌───────────────▼───────┐   ┌──────────────────────────────────────┐
            │ EXECUTED_NO_SIGNAL    │   │ Create Finding Object                │
            │ (tracked, not hidden)│   │ - vuln type                           │
            └───────────────────────┘   │ - endpoint                           │
                                        │ - payload                            │
                                        │ - evidence                           │
                                        └───────────────────┬──────────────────┘
                                                            ↓
            ┌──────────────────────────────────────┐
            │ Phase 4: Intelligence Correlation     │
            │ - deduplicate findings                │
            │ - corroboration bonus                 │
            │ - tool confidence merge               │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ OWASP / Risk Engine                   │
            │ - category mapping                    │
            │ - impact × likelihood                 │
            │ - final 0–100 score                   │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Reporting Engine                      │
            │ - vuln-centric model                  │
            │ - JSON                                │
            │ - HTML                                │
            │ - coverage gaps                       │
            └───────────────────┬──────────────────┘
                                ↓
            ┌──────────────────────────────────────┐
            │ Scan Termination                      │
            │ - success                             │
            │ - partial                             │
            │ - blocked                             │
            └──────────────────────────────────────┘
