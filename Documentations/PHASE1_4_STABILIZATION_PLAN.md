# Phase 1-4 Stabilization Plan

**Date**: 2026-01-12  
**Objective**: Complete and stabilize Phases 1-4 ONLY. NO Phase 5.  
**Status**: 🟡 In Progress

---

## Executive Summary

**Current Reality**:
- ✅ Phase 1 (Discovery): Architecturally sound, needs hardening
- ⚠️ Phase 2 (Crawling): **CRITICAL GAP** - Katana exists but not integrated properly
- ⚠️ Phase 3 (Payload Testing): Tools exist but lack crawler-driven inputs
- ⚠️ Phase 4 (Correlation): Engines exist but inputs are shallow

**Root Cause**: Built Phase 4 "production maturity" features before Phase 2-3 foundations were solid.

**Solution**: Fix in strict order: Phase 2 → Phase 3 → Phase 4 → Phase 1 hardening

---

## 🚫 Hard Constraints (DO NOT VIOLATE)

- ❌ NO Phase 5 (traffic replay, regression, etc.)
- ❌ NO UI/dashboards/frontend
- ❌ NO random tool additions without gating logic
- ❌ NO payload tools without crawler-verified inputs
- ❌ NO marking SKIPPED tools as success

---

## 📋 Stabilization Checklist

### Phase 2: Crawling & Expansion (CRITICAL - DO FIRST)

**Current State**:
- ✅ `katana_crawler.py` exists (302 lines)
- ✅ `light_crawler.py` exists (fallback)
- ✅ `crawler_integration.py` exists
- ❌ NOT integrated as mandatory Phase 2 step
- ❌ NOT populating `DiscoveryCache` properly
- ❌ NOT used by payload tools

**Required Fixes** (Priority 1):

- [ ] **Make crawler mandatory**
  - [ ] Crawler MUST run before any payload tool
  - [ ] No payload tool may run without crawler confirmation
  - [ ] Crawler failure = BLOCK payload phase

- [ ] **Fix crawler integration**
  - [ ] Ensure `katana_crawler.py` populates:
    - [ ] `endpoints` (Set[str])
    - [ ] `parameters` (Dict[str, Set[str]])
    - [ ] `forms` (List[Dict])
    - [ ] `api_endpoints` (List[str])
  - [ ] Verify crawler executes JavaScript
  - [ ] Track discovery source per endpoint
  - [ ] Set confidence levels

- [ ] **Populate DiscoveryCache**
  - [ ] `DiscoveryCache.endpoints` = crawler.endpoints
  - [ ] `DiscoveryCache.params` = crawler.parameters
  - [ ] `DiscoveryCache.forms` = crawler.forms
  - [ ] `DiscoveryCache.api_endpoints` = crawler.api_endpoints
  - [ ] Mark all as `source="crawler"`

- [ ] **Validate EndpointGraph**
  - [ ] `EndpointGraph.add_crawl_result()` called for each endpoint
  - [ ] Graph tracks: endpoint → method → params → sources
  - [ ] Graph is finalized before payload tools run
  - [ ] Graph queries work:
    - [ ] `get_reflectable_endpoints()`
    - [ ] `get_injectable_sql_endpoints()`
    - [ ] `get_parametric_endpoints()`

**Success Criteria**:
- ✅ Crawler runs first, produces endpoints + params + forms
- ✅ EndpointGraph built from crawler data
- ✅ No payload tool runs without crawler confirmation

**Files to Fix**:
- `phase2_pipeline.py` - Make crawler mandatory
- `katana_crawler.py` - Ensure proper output parsing
- `endpoint_graph.py` - Validate graph building
- `cache_discovery.py` - Ensure crawler populates cache

---

### Phase 3: Payload-Driven Testing (DO SECOND)

**Current State**:
- ✅ Payload tools exist: `dalfox`, `sqlmap`, `commix`, etc.
- ❌ NOT gated by crawler results
- ❌ NOT using EndpointGraph for targeting
- ❌ Inputs are weak/random

**Required Fixes** (Priority 2):

- [ ] **Strict Gating**
  - [ ] Dalfox runs ONLY on `graph.get_reflectable_endpoints()`
  - [ ] SQLMap runs ONLY on `graph.get_injectable_sql_endpoints()`
  - [ ] Commix runs ONLY on `graph.get_injectable_cmd_endpoints()`
  - [ ] Nuclei runs on all endpoints (broad scan)

- [ ] **Input Verification**
  - [ ] Each payload tool receives:
    - [ ] Endpoint URL
    - [ ] Parameter list (from crawler)
    - [ ] Method (GET/POST)
    - [ ] Confidence score
  - [ ] No blind fuzzing
  - [ ] No spray-and-pray

- [ ] **Payload Attempt Tracking**
  - [ ] Log each payload sent
  - [ ] Track success vs failure ratio
  - [ ] Record evidence (reflection, execution)

- [ ] **Finding Quality**
  - [ ] Each finding must include:
    - [ ] Entry point (endpoint + parameter)
    - [ ] Payload used
    - [ ] Evidence (response snippet)
    - [ ] Confidence score
    - [ ] Tool name

**Success Criteria**:
- ✅ Payload tools run ONLY on crawler-verified endpoints
- ✅ Each payload has clear entry point and evidence
- ✅ No random fuzzing

**Files to Fix**:
- `strict_gating_loop.py` - Enforce crawler-driven gating
- Individual tool wrappers (dalfox, sqlmap, etc.)
- `decision_ledger.py` - Ensure prerequisites check crawler data

---

### Phase 4: Correlation, Risk, Confidence (DO THIRD)

**Current State**:
- ✅ `finding_correlator.py` exists (Phase 3)
- ✅ `risk_engine.py` exists (Phase 3)
- ✅ `api_discovery.py` exists (Phase 3)
- ❌ Inputs are shallow (not using crawler depth, JS visibility, etc.)
- ❌ Confidence scores lack context

**Required Fixes** (Priority 3):

- [ ] **Enhance Confidence Scoring**
  - [ ] Consider:
    - [ ] Crawl depth (deeper = less confident)
    - [ ] JS execution visibility
    - [ ] Payload confirmation (reflected? executed?)
    - [ ] Reproducibility (same result twice?)
  - [ ] Multi-tool agreement increases confidence

- [ ] **Risk Engine**
  - [ ] Map findings to OWASP Top 10
  - [ ] Aggregate duplicate issues
  - [ ] De-duplicate across tools
  - [ ] Calculate risk score based on:
    - [ ] Severity
    - [ ] Confidence
    - [ ] Exploitability
    - [ ] Business impact

- [ ] **Reports**
  - [ ] Clearly separate:
    - [ ] Informational (confidence < 30%)
    - [ ] Suspected (confidence 30-70%)
    - [ ] Confirmed (confidence > 70%)
  - [ ] Explain risk scores
  - [ ] Show tool agreement

- [ ] **CI Output**
  - [ ] Deterministic
  - [ ] Fail ONLY on confirmed findings (confidence > 70%)
  - [ ] Warn on suspected findings

**Success Criteria**:
- ✅ Confidence scores are explainable
- ✅ Risk engine considers crawler context
- ✅ Reports tell coherent story

**Files to Fix**:
- `finding_correlator.py` - Use crawler depth/JS data
- `risk_engine.py` - Enhance confidence calculation
- `ci_integration.py` - Fail only on confirmed findings

---

### Phase 1: Recon & Decision Engine (DO LAST - HARDENING)

**Current State**:
- ✅ Architecturally correct
- ✅ Signal-driven
- ✅ Budget-aware
- ⚠️ Needs hardening, not expansion

**Required Fixes** (Priority 4):

- [ ] **Tool Audit**
  - [ ] Each tool has ONE clear purpose
  - [ ] Each tool produces ONE signal type
  - [ ] No tool runs "just because"

- [ ] **Signal Clarity**
  - [ ] Every tool execution explains WHY it ran
  - [ ] `EXECUTED_NO_SIGNAL` is NOT success
  - [ ] `failure_reason` enums normalized

- [ ] **HTTPS Probe Immutability**
  - [ ] Result is immutable post-planning
  - [ ] No re-probing during execution

- [ ] **DiscoveryCache Authority**
  - [ ] DiscoveryCache is ONLY source of truth
  - [ ] No direct cache bypass

**Success Criteria**:
- ✅ Clean execution graph
- ✅ Zero ambiguity in tool decisions
- ✅ All signals traceable

**Files to Audit**:
- `decision_ledger.py`
- Individual tool wrappers
- `cache_discovery.py`

---

## 🎯 Implementation Order

### Week 1: Phase 2 Stabilization (CRITICAL)

**Day 1-2**: Crawler Integration
- Fix `katana_crawler.py` output parsing
- Ensure crawler populates `DiscoveryCache`
- Make crawler mandatory in `phase2_pipeline.py`

**Day 3-4**: EndpointGraph Validation
- Verify `endpoint_graph.py` builds from crawler data
- Test graph queries
- Ensure graph is finalized before payload phase

**Day 5**: Testing
- Run full Phase 2 test suite
- Validate crawler → graph → cache flow
- Document gaps

### Week 2: Phase 3 Stabilization

**Day 1-2**: Strict Gating
- Fix `strict_gating_loop.py` to use crawler data
- Ensure Dalfox runs ONLY on reflectable endpoints
- Ensure SQLMap runs ONLY on SQL-injectable endpoints

**Day 3-4**: Input Verification
- Update payload tool wrappers to accept crawler inputs
- Add payload attempt tracking
- Improve finding quality

**Day 5**: Testing
- Run full Phase 3 test suite
- Validate gating logic
- Document gaps

### Week 3: Phase 4 & 1 Stabilization

**Day 1-2**: Confidence & Risk
- Enhance confidence scoring (crawler depth, JS visibility)
- Fix risk engine to use crawler context
- Update reports

**Day 3**: CI Output
- Make CI output deterministic
- Fail only on confirmed findings

**Day 4-5**: Phase 1 Hardening
- Audit tool purposes
- Normalize signals
- Fix ambiguities

---

## 🔍 Validation Checklist (MANDATORY)

Before declaring completion:

- [ ] ✅ Crawler drives payload scope
- [ ] ✅ No payload tool runs without crawl evidence
- [ ] ✅ No skipped tool is marked successful
- [ ] ✅ OWASP mapping is explicit
- [ ] ✅ Confidence scores are explainable
- [ ] ✅ Reports tell a coherent story
- [ ] ✅ Phase boundaries are respected

---

## 🛑 Explicit Non-Goals (DO NOT TOUCH)

- ❌ No auto-exploitation
- ❌ No credential stuffing
- ❌ No brute-force auth
- ❌ No DoS testing
- ❌ **NO PHASE 5** (traffic replay, regression, etc.)

---

## 📁 Key Files to Focus On

### Phase 2 (Crawling)
- `katana_crawler.py` - Main crawler
- `light_crawler.py` - Fallback
- `crawler_integration.py` - Integration layer
- `endpoint_graph.py` - Graph builder
- `cache_discovery.py` - Cache population
- `phase2_pipeline.py` - Orchestration

### Phase 3 (Payload Testing)
- `strict_gating_loop.py` - Gating logic
- Individual tool wrappers (dalfox, sqlmap, commix, etc.)
- `decision_ledger.py` - Prerequisites

### Phase 4 (Correlation)
- `finding_correlator.py` - Multi-tool dedup
- `risk_engine.py` - Risk scoring
- `api_discovery.py` - API detection

### Phase 1 (Discovery)
- All recon tools
- `cache_discovery.py`
- `decision_ledger.py`

---

## 🎬 End State Definition

**When done correctly**:
- ✅ Crawler is mandatory Phase 2 step
- ✅ EndpointGraph built from crawler data
- ✅ Payload tools gated by crawler evidence
- ✅ Confidence scores consider crawler context
- ✅ Reports are explainable and coherent
- ✅ All phase boundaries respected

**Result**: A professional, architecture-driven vulnerability assessment engine with stateful crawling and targeted attack simulation.

---

**Status**: 🟡 In Progress  
**Next Action**: Fix Phase 2 crawler integration  
**Blocker**: None  
**ETA**: 3 weeks for full stabilization
