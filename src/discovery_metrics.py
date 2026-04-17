"""Discovery quality metrics and hard fail-fast policy helpers."""

from typing import Dict


def collect_discovery_metrics(
    endpoints_total: int,
    api_endpoints: int,
    params_total: int,
    reflections: int,
    js_calls: int,
    zap_urls: int,
    gau_urls: int = 0,
    wayback_urls: int = 0,
    hakrawler_urls: int = 0,
    js_regex_urls: int = 0,
) -> Dict[str, int]:
    return {
        "endpoints_total": int(endpoints_total or 0),
        "api_endpoints": int(api_endpoints or 0),
        "params_total": int(params_total or 0),
        "reflections": int(reflections or 0),
        "js_calls": int(js_calls or 0),
        "zap_urls": int(zap_urls or 0),
        "gau_urls": int(gau_urls or 0),
        "wayback_urls": int(wayback_urls or 0),
        "hakrawler_urls": int(hakrawler_urls or 0),
        "js_regex_urls": int(js_regex_urls or 0),
    }


def assess_discovery_status(metrics: Dict[str, int]) -> str:
    params_total = int(metrics.get("params_total", 0) or 0)
    endpoints_total = int(metrics.get("endpoints_total", 0) or 0)
    api_endpoints = int(metrics.get("api_endpoints", 0) or 0)
    source_urls = (
        int(metrics.get("zap_urls", 0) or 0)
        + int(metrics.get("gau_urls", 0) or 0)
        + int(metrics.get("wayback_urls", 0) or 0)
        + int(metrics.get("hakrawler_urls", 0) or 0)
        + int(metrics.get("js_regex_urls", 0) or 0)
    )

    if endpoints_total == 0 and params_total == 0:
        return "FAILED"
    if endpoints_total >= 30 or params_total >= 20:
        return "STRONG"
    if endpoints_total >= 30 or params_total >= 10:
        return "ACCEPTABLE"
    if (
        endpoints_total >= 5
        or params_total >= 3
        or api_endpoints > 0
        or source_urls > 0
    ):
        return "ACCEPTABLE"
    if endpoints_total >= 1 or params_total >= 1:
        return "WEAK"
    return "FAILED"
