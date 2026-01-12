#!/usr/bin/env python3
"""
Test Phase 1-4 Integration
===========================

Validates that all Phase 1-4 hardening modules are properly integrated.
"""

import sys
from pathlib import Path

# Test imports
def test_imports():
    """Test that all Phase 1-4 modules can be imported"""
    print("Testing imports...")
    
    try:
        from discovery_classification import get_tool_contract, is_signal_producer, DISCOVERY_TOOLS
        print("✓ discovery_classification imported")
        
        from discovery_completeness import DiscoveryCompletenessEvaluator, CompletenessReport
        print("✓ discovery_completeness imported")
        
        from payload_strategy import PayloadStrategy, PayloadReadinessGate, PayloadType
        print("✓ payload_strategy imported")
        
        from owasp_mapping import map_to_owasp, OWASPCategory, get_owasp_description
        print("✓ owasp_mapping imported")
        
        from enhanced_confidence import EnhancedConfidenceEngine, ConfidenceFactors
        print("✓ enhanced_confidence imported")
        
        from deduplication_engine import DeduplicationEngine, DuplicateGroup
        print("✓ deduplication_engine imported")
        
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


def test_discovery_classification():
    """Test discovery classification system"""
    print("\nTesting discovery classification...")
    
    from discovery_classification import get_tool_contract, is_signal_producer, DISCOVERY_TOOLS
    
    # Test tool contract retrieval
    dig_contract = get_tool_contract("dig_a")
    assert dig_contract is not None, "dig_a contract not found"
    assert "dns_resolved" in dig_contract.signals_produced, "dig_a should produce dns_resolved signal"
    print(f"✓ dig_a contract: {dig_contract.classification.value}, confidence={dig_contract.confidence_weight}")
    
    # Test signal producer check
    assert is_signal_producer("nmap_quick") == True, "nmap_quick should be signal producer"
    assert is_signal_producer("gobuster") == False, "gobuster should not be signal producer"
    print("✓ Signal producer classification working")
    
    # Test all tools registered
    assert len(DISCOVERY_TOOLS) >= 10, f"Expected at least 10 tools, got {len(DISCOVERY_TOOLS)}"
    print(f"✓ {len(DISCOVERY_TOOLS)} discovery tools classified")
    
    return True


def test_owasp_mapping():
    """Test OWASP mapping system"""
    print("\nTesting OWASP mapping...")
    
    from owasp_mapping import map_to_owasp, OWASPCategory, get_owasp_description
    
    # Test XSS mapping
    xss_cat = map_to_owasp("xss")
    assert xss_cat == OWASPCategory.A03_INJECTION, f"XSS should map to A03, got {xss_cat}"
    print(f"✓ XSS → {xss_cat.value}")
    
    # Test SQLi mapping
    sqli_cat = map_to_owasp("sql_injection")
    assert sqli_cat == OWASPCategory.A03_INJECTION, f"SQLi should map to A03, got {sqli_cat}"
    print(f"✓ SQLi → {sqli_cat.value}")
    
    # Test SSRF mapping
    ssrf_cat = map_to_owasp("ssrf")
    assert ssrf_cat == OWASPCategory.A10_SSRF, f"SSRF should map to A10, got {ssrf_cat}"
    print(f"✓ SSRF → {ssrf_cat.value}")
    
    # Test description
    desc = get_owasp_description(OWASPCategory.A03_INJECTION)
    assert "injection" in desc.lower(), "A03 description should mention injection"
    print(f"✓ OWASP descriptions available")
    
    return True


def test_payload_strategy():
    """Test payload strategy system"""
    print("\nTesting payload strategy...")
    
    from payload_strategy import PayloadStrategy, PayloadType
    
    strategy = PayloadStrategy()
    
    # Test XSS payloads
    xss_payloads = strategy.generate_xss_payloads("search", "https://example.com", "GET")
    assert len(xss_payloads) > 0, "Should generate XSS payloads"
    assert any("<script>" in p.get("payload", "") for p in xss_payloads), "Should include script tags"
    print(f"✓ Generated {len(xss_payloads)} XSS payloads")
    
    # Test SQLi payloads
    sqli_payloads = strategy.generate_sqli_payloads("id", "https://example.com/user", "GET")
    assert len(sqli_payloads) > 0, "Should generate SQLi payloads"
    assert any("'" in p.get("payload", "") for p in sqli_payloads), "Should include SQL quotes"
    print(f"✓ Generated {len(sqli_payloads)} SQLi payloads")
    
    # Test payload tracking (pass PayloadType enum)
    strategy.track_attempt(
        payload="<script>alert(1)</script>",
        payload_type=PayloadType.BASELINE,
        endpoint="https://example.com",
        parameter="q",
        method="GET",
        success=True,
        evidence="Reflected in response"
    )
    summary = strategy.get_attempts_summary()
    assert summary["total_attempts"] == 1, "Should track 1 attempt"
    assert summary["successful_attempts"] == 1, "Should track 1 success"
    print("✓ Payload tracking working")
    
    return True


def test_enhanced_confidence():
    """Test enhanced confidence scoring"""
    print("\nTesting enhanced confidence scoring...")
    
    from enhanced_confidence import EnhancedConfidenceEngine
    
    engine = EnhancedConfidenceEngine()
    
    # Test basic confidence calculation
    factors = engine.calculate_confidence(
        finding_type="xss",
        tool_name="dalfox",
        evidence="Reflected payload: <script>alert(1)</script>",
        corroborating_tools=[],
        crawler_verified=True
    )
    
    assert factors.final_score > 0, "Should calculate confidence score"
    assert factors.final_score <= 100, "Score should not exceed 100"
    print(f"✓ Single tool confidence: {factors.final_score}/100 ({factors.tool_confidence + factors.payload_confidence} base)")
    
    # Test corroboration bonus
    factors_corr = engine.calculate_confidence(
        finding_type="xss",
        tool_name="dalfox",
        evidence="Reflected payload",
        corroborating_tools=["nuclei", "xsstrike"],
        crawler_verified=True
    )
    
    assert factors_corr.corroboration_bonus > 0, "Should apply corroboration bonus"
    assert factors_corr.final_score > factors.final_score, "Corroboration should boost confidence"
    print(f"✓ Corroborated confidence: {factors_corr.final_score}/100 (+{factors_corr.corroboration_bonus} bonus)")
    
    # Test confidence labels
    label_high = engine.get_confidence_label(85)
    assert label_high == "High", f"85 should be High, got {label_high}"
    label_low = engine.get_confidence_label(35)
    assert label_low == "Very Low", f"35 should be Very Low, got {label_low}"
    print("✓ Confidence labels working")
    
    return True


def test_deduplication():
    """Test deduplication engine"""
    print("\nTesting deduplication...")
    
    from deduplication_engine import DeduplicationEngine
    
    engine = DeduplicationEngine()
    
    # Create duplicate findings
    findings = [
        {
            "type": "xss",
            "endpoint": "https://example.com/search",
            "severity": "high",
            "tool": "dalfox",
            "evidence": "Payload reflected",
            "confidence": 75
        },
        {
            "type": "xss",
            "endpoint": "https://example.com/search?q=test",  # Same endpoint, different query
            "severity": "medium",
            "tool": "nuclei",
            "evidence": "XSS detected",
            "confidence": 60
        },
        {
            "type": "sqli",
            "endpoint": "https://example.com/user",
            "severity": "critical",
            "tool": "sqlmap",
            "evidence": "SQL injection confirmed",
            "confidence": 90
        }
    ]
    
    deduplicated = engine.deduplicate(findings)
    
    # Should merge the two XSS findings
    assert len(deduplicated) == 2, f"Should have 2 unique findings, got {len(deduplicated)}"
    
    # Find the XSS finding
    xss_finding = next((f for f in deduplicated if f["type"] == "xss"), None)
    assert xss_finding is not None, "XSS finding should exist"
    assert xss_finding["severity"] == "high", "Should keep highest severity"
    assert "corroborating_tools" in xss_finding, "Should have corroborating tools"
    assert len(xss_finding["corroborating_tools"]) == 1, "Should have 1 corroborating tool"
    print(f"✓ Deduplicated {len(findings)} → {len(deduplicated)} findings")
    
    # Test deduplication report
    report = engine.get_deduplication_report()
    assert report["duplicate_groups"] >= 0, "Should have deduplication report"
    print(f"✓ Deduplication report: {report['duplicate_groups']} groups, {report['total_duplicates_removed']} removed")
    
    return True


def test_scanner_integration():
    """Test that automation_scanner_v2.py has all integrations"""
    print("\nTesting scanner integration...")
    
    # Read the scanner file
    scanner_path = Path("automation_scanner_v2.py")
    if not scanner_path.exists():
        print("✗ automation_scanner_v2.py not found")
        return False
    
    content = scanner_path.read_text()
    
    # Check imports
    required_imports = [
        "from discovery_classification import",
        "from discovery_completeness import",
        "from payload_strategy import",
        "from owasp_mapping import",
        "from enhanced_confidence import",
        "from deduplication_engine import"
    ]
    
    for imp in required_imports:
        if imp not in content:
            print(f"✗ Missing import: {imp}")
            return False
    print("✓ All Phase 1-4 imports present")
    
    # Check initialization
    if "self.discovery_evaluator" not in content:
        print("✗ Missing discovery_evaluator initialization")
        return False
    if "self.payload_strategy" not in content:
        print("✗ Missing payload_strategy initialization")
        return False
    if "self.enhanced_confidence" not in content:
        print("✗ Missing enhanced_confidence initialization")
        return False
    if "self.dedup_engine" not in content:
        print("✗ Missing dedup_engine initialization")
        return False
    print("✓ All engines initialized")
    
    # Check report integration
    if "discovery_completeness" not in content:
        print("✗ Missing discovery_completeness in report")
        return False
    if "deduplication" not in content:
        print("✗ Missing deduplication in report")
        return False
    if "payload_attempts" not in content:
        print("✗ Missing payload_attempts in report")
        return False
    print("✓ Report sections integrated")
    
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("Phase 1-4 Integration Test Suite")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("Discovery Classification", test_discovery_classification),
        ("OWASP Mapping", test_owasp_mapping),
        ("Payload Strategy", test_payload_strategy),
        ("Enhanced Confidence", test_enhanced_confidence),
        ("Deduplication", test_deduplication),
        ("Scanner Integration", test_scanner_integration),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ {name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL PHASE 1-4 INTEGRATIONS WORKING!")
        return 0
    else:
        print("\n⚠️  Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
