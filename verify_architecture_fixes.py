#!/usr/bin/env python3
"""
Verification Test: Architecture Fixes V5
Tests that all 7 fixes are properly implemented.
"""

import sys
from pathlib import Path

# Add VAPT-Automated-Engine to path
sys.path.insert(0, str(Path(__file__).parent / "VAPT-Automated-Engine"))

from cache_discovery import DiscoveryCache
from execution_paths import RootDomainExecutor, SubdomainExecutor
from decision_ledger import DecisionLedger
from target_profile import TargetProfile, TargetType


def test_fix_1_nuclei_signal_flow():
    """Fix #1: Nuclei should not require live_endpoints, only web_target."""
    from decision_ledger import DecisionEngine
    
    profile = TargetProfile.from_target("https://example.com")
    ledger = DecisionEngine.build_ledger(profile)
    executor = RootDomainExecutor(profile, ledger)
    plan = executor.get_execution_plan()
    
    # Find nuclei tools in plan
    nuclei_tools = [(t, c, m) for t, c, m in plan if "nuclei" in t]
    
    assert len(nuclei_tools) > 0, "Nuclei tools not in plan"
    
    for tool, cmd, meta in nuclei_tools:
        requires = meta.get("requires", set())
        optional = meta.get("optional", set())
        
        assert "web_target" in requires, f"Nuclei {tool} missing web_target in requires"
        assert "live_endpoints" not in requires, f"Nuclei {tool} should not require live_endpoints (should be optional)"
        assert "live_endpoints" in optional, f"Nuclei {tool} should have live_endpoints as optional"
    
    print("✅ Fix #1: Nuclei signal flow correct")


def test_fix_2_live_endpoint_method():
    """Fix #2: Cache should have add_live_endpoint method."""
    cache = DiscoveryCache()
    
    assert hasattr(cache, "add_live_endpoint"), "Cache missing add_live_endpoint method"
    
    # Test that it works
    cache.add_live_endpoint("/admin")
    assert "/admin" in cache.live_endpoints, "Live endpoint not added"
    assert "/admin" in cache.endpoints, "Live endpoint should also be in general endpoints"
    
    print("✅ Fix #2: add_live_endpoint method implemented")


def test_fix_3_nikto_sigpipe():
    """Fix #3: Nikto rc=141 should be handled (verify signature exists)."""
    from automation_scanner_v2 import AutomationScannerV2, ToolOutcome
    
    # Just verify the classification method exists and handles rc=141
    scanner = AutomationScannerV2(
        "https://example.com",
        skip_tool_check=True
    )
    
    # Test classification with rc=141
    outcome, status = scanner._classify_execution_outcome("nikto", 141, True)
    assert outcome == ToolOutcome.SUCCESS_WITH_FINDINGS, "rc=141 nikto should be SUCCESS_WITH_FINDINGS"
    assert status == "PARTIAL", "rc=141 nikto should have PARTIAL status"
    
    print("✅ Fix #3: Nikto SIGPIPE (rc=141) handled correctly")


def test_fix_4_terminology():
    """Fix #4: Decision layer should have clear terminology."""
    from automation_scanner_v2 import DecisionOutcome
    
    # Verify DecisionOutcome enum exists with correct values
    assert hasattr(DecisionOutcome, "ALLOW")
    assert hasattr(DecisionOutcome, "BLOCK")
    assert hasattr(DecisionOutcome, "SKIP")
    
    print("✅ Fix #4: State terminology clear (ALLOW, BLOCK, SKIP)")


def test_fix_5_dns_consolidation():
    """Fix #5: DNS tools should be consolidated."""
    from decision_ledger import DecisionEngine
    
    profile = TargetProfile.from_target("example.com")
    ledger = DecisionEngine.build_ledger(profile)
    
    # Root domain executor
    root_executor = RootDomainExecutor(profile, ledger)
    root_plan = root_executor.get_execution_plan()
    
    # Find DNS tools
    dns_tools_root = [t for t, c, m in root_plan if m.get("category") == "DNS"]
    assert "dnsrecon" in dns_tools_root, "Root domain should use dnsrecon"
    assert "dig_a" not in dns_tools_root, "Root domain should not have dig_a (consolidated into dnsrecon)"
    assert "dig_ns" not in dns_tools_root, "Root domain should not have dig_ns"
    assert "dig_mx" not in dns_tools_root, "Root domain should not have dig_mx"
    
    # Subdomain executor
    subdomain_profile = TargetProfile.from_target("sub.example.com")
    subdomain_ledger = DecisionEngine.build_ledger(subdomain_profile)
    subdomain_executor = SubdomainExecutor(subdomain_profile, subdomain_ledger)
    subdomain_plan = subdomain_executor.get_execution_plan()
    
    dns_tools_sub = [t for t, c, m in subdomain_plan if m.get("category") == "DNS"]
    assert "dig_a" in dns_tools_sub, "Subdomain should have dig_a"
    assert "dig_aaaa" not in dns_tools_sub, "Subdomain should not have dig_aaaa (removed)"
    
    print("✅ Fix #5: DNS tools consolidated (dnsrecon for root, dig_a for subdomain)")


def test_fix_6_run_tool_split():
    """Fix #6: _run_tool should delegate to focused helpers."""
    from automation_scanner_v2 import AutomationScannerV2
    
    scanner = AutomationScannerV2(
        "https://example.com",
        skip_tool_check=True
    )
    
    # Verify helper methods exist
    assert hasattr(scanner, "_execute_tool_subprocess"), "Missing _execute_tool_subprocess"
    assert hasattr(scanner, "_classify_execution_outcome"), "Missing _classify_execution_outcome"
    assert callable(scanner._execute_tool_subprocess), "_execute_tool_subprocess not callable"
    assert callable(scanner._classify_execution_outcome), "_classify_execution_outcome not callable"
    
    print("✅ Fix #6: _run_tool responsibility split into focused helpers")


def test_fix_7_removed_gate_mode():
    """Fix #7: Gate mode should be removed."""
    from automation_scanner_v2 import AutomationScannerV2
    import inspect
    
    # Check that run_gate_scan method is removed
    assert not hasattr(AutomationScannerV2, "run_gate_scan"), "run_gate_scan should be removed"
    
    # Verify main still works without mode parameter
    scanner = AutomationScannerV2(
        "https://example.com",
        skip_tool_check=True
    )
    
    print("✅ Fix #7: Gate mode removed, single execution path")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("ARCHITECTURE FIXES V5 - VERIFICATION TEST")
    print("=" * 60 + "\n")
    
    try:
        test_fix_1_nuclei_signal_flow()
        test_fix_2_live_endpoint_method()
        test_fix_3_nikto_sigpipe()
        test_fix_4_terminology()
        test_fix_5_dns_consolidation()
        test_fix_6_run_tool_split()
        test_fix_7_removed_gate_mode()
        
        print("\n" + "=" * 60)
        print("✅ ALL FIXES VERIFIED - v5 Architecture Ready")
        print("=" * 60 + "\n")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
