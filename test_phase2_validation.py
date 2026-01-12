"""
Validation Test for Phase 2 - Crawler → Cache → Graph Integration
Purpose: Verify that crawler properly populates cache and graph with endpoints/params
"""

import logging
from cache_discovery import DiscoveryCache
from endpoint_graph import EndpointGraph
from crawler_mandatory_gate import CrawlerMandatoryGate, CrawlerStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_cache_population():
    """Test: Cache gets populated by crawler integration"""
    cache = DiscoveryCache()
    
    # Simulate crawler populating cache
    cache.add_endpoint("/api/users")
    cache.add_endpoint("/api/posts")
    cache.add_param("id")
    cache.add_param("search")
    cache.add_reflection("hint:search")
    
    # Validate
    assert len(cache.endpoints) == 2, f"Expected 2 endpoints, got {len(cache.endpoints)}"
    assert len(cache.params) == 2, f"Expected 2 params, got {len(cache.params)}"
    assert len(cache.reflections) > 0, f"Expected reflections, got {len(cache.reflections)}"
    
    logger.info("✓ Cache population test PASSED")
    return True


def test_graph_building():
    """Test: EndpointGraph builds correctly from crawler data"""
    graph = EndpointGraph(target="https://example.com")
    
    # Simulate crawler results
    graph.add_crawl_result(
        url="/api/users",
        method="GET",
        params={"id": ["123"], "filter": ["admin"]},
        is_api=True,
        status_code=200
    )
    
    graph.add_crawl_result(
        url="/search",
        method="GET",
        params={"q": ["test"], "category": ["products"]},
        is_api=False,
        status_code=200
    )
    
    # Mark reflections
    graph.mark_reflectable("q")
    graph.mark_injectable_sql("id")
    
    graph.finalize()
    
    # Validate queries
    all_endpoints = graph.get_all_endpoints()
    assert len(all_endpoints) == 2, f"Expected 2 endpoints, got {len(all_endpoints)}"
    
    reflectable = graph.get_reflectable_endpoints()
    assert "/search" in reflectable, f"Expected /search in reflectable, got {reflectable}"
    
    sql_injectable = graph.get_injectable_sql_endpoints()
    assert "/api/users" in sql_injectable, f"Expected /api/users in SQL injectable, got {sql_injectable}"
    
    parametric = graph.get_parametric_endpoints()
    assert len(parametric) == 2, f"Expected 2 parametric endpoints, got {len(parametric)}"
    
    logger.info("✓ Graph building test PASSED")
    logger.info(f"  Graph summary: {graph.get_summary()}")
    return True


def test_crawler_mandatory_gate():
    """Test: CrawlerMandatoryGate enforces crawler requirement"""
    
    # Test 1: Gate with empty cache (crawler failed)
    cache_empty = DiscoveryCache()
    gate_fail = CrawlerMandatoryGate(cache_empty)
    
    status, reason = gate_fail.check_crawler_status()
    assert status == CrawlerStatus.FAILED, f"Expected FAILED, got {status}"
    assert not gate_fail.crawler_succeeded(), "Expected crawler_succeeded() = False"
    
    blocked_tools = gate_fail.get_blocked_tools()
    assert "dalfox" in blocked_tools, f"Expected dalfox blocked, got {blocked_tools}"
    assert "sqlmap" in blocked_tools, f"Expected sqlmap blocked, got {blocked_tools}"
    
    logger.info("✓ CrawlerMandatoryGate (failure case) test PASSED")
    
    # Test 2: Gate with populated cache (crawler succeeded)
    cache_ok = DiscoveryCache()
    cache_ok.add_endpoint("/api/users")
    cache_ok.add_param("id")
    
    graph_ok = EndpointGraph(target="https://example.com")
    graph_ok.add_crawl_result("/api/users", params={"id": ["123"]})
    graph_ok.finalize()
    
    gate_ok = CrawlerMandatoryGate(cache_ok, graph_ok)
    
    status, reason = gate_ok.check_crawler_status()
    assert status == CrawlerStatus.SUCCESS, f"Expected SUCCESS, got {status}"
    assert gate_ok.crawler_succeeded(), "Expected crawler_succeeded() = True"
    
    blocked_tools = gate_ok.get_blocked_tools()
    assert len(blocked_tools) == 0, f"Expected no blocked tools, got {blocked_tools}"
    
    logger.info("✓ CrawlerMandatoryGate (success case) test PASSED")
    
    # Test 3: Gate report
    report = gate_ok.get_gate_report()
    assert report['crawler_succeeded'] == True, "Expected crawler_succeeded in report"
    assert report['endpoints_discovered'] == 1, f"Expected 1 endpoint, got {report['endpoints_discovered']}"
    
    logger.info("✓ CrawlerMandatoryGate report test PASSED")
    logger.info(f"  Report: {report}")
    return True


def test_parameter_flag_population():
    """Test: Parameter flags populated from cache signals"""
    cache = DiscoveryCache()
    cache.add_endpoint("/api/users")
    cache.add_param("search")
    cache.add_param("cmd")
    cache.add_param("user_id")
    cache.add_reflection("hint:search")
    cache.command_params.add("cmd")
    
    graph = EndpointGraph(target="https://example.com")
    graph.add_crawl_result("/api/users", params={"search": ["test"], "cmd": ["ls"], "user_id": ["123"]})
    graph.finalize()
    
    gate = CrawlerMandatoryGate(cache, graph)
    gate.check_crawler_status()  # This populates flags
    
    # Validate flags were set
    assert graph.get_parameter("search").reflectable == True, "Expected search to be reflectable"
    assert graph.get_parameter("cmd").injectable_cmd == True, "Expected cmd to be cmd-injectable"
    assert graph.get_parameter("user_id").injectable_sql == True, "Expected user_id to be SQL-injectable"
    
    logger.info("✓ Parameter flag population test PASSED")
    return True


def run_all_tests():
    """Run all Phase 2 validation tests"""
    logger.info("=" * 80)
    logger.info("PHASE 2 VALIDATION TESTS - Crawler → Cache → Graph Integration")
    logger.info("=" * 80)
    
    tests = [
        ("Cache Population", test_cache_population),
        ("Graph Building", test_graph_building),
        ("Crawler Mandatory Gate", test_crawler_mandatory_gate),
        ("Parameter Flag Population", test_parameter_flag_population),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            logger.info(f"\nRunning: {name}...")
            if test_func():
                passed += 1
        except AssertionError as e:
            logger.error(f"✗ {name} FAILED: {e}")
            failed += 1
        except Exception as e:
            logger.error(f"✗ {name} ERROR: {e}")
            failed += 1
    
    logger.info("\n" + "=" * 80)
    logger.info(f"RESULTS: {passed} passed, {failed} failed")
    logger.info("=" * 80)
    
    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
