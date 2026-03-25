"""Discovery quality metrics and hard fail-fast policy helpers."""

from typing import Dict


def collect_discovery_metrics(
    endpoints_total: int,
    api_endpoints: int,
    params_total: int,
    reflections: int,
    js_calls: int,
    zap_urls: int,
) -> Dict[str, int]:
    return {
        "endpoints_total": int(endpoints_total or 0),
        "api_endpoints": int(api_endpoints or 0),
        "params_total": int(params_total or 0),
        "reflections": int(reflections or 0),
        "js_calls": int(js_calls or 0),
        "zap_urls": int(zap_urls or 0),
    }


def assess_discovery_status(metrics: Dict[str, int]) -> str:
    params_total = int(metrics.get("params_total", 0) or 0)
    api_calls = int(metrics.get("js_calls", 0) or 0)
    endpoints_total = int(metrics.get("endpoints_total", 0) or 0)

    if endpoints_total == 0:
        return "FAILED"
    if params_total < 10 or api_calls == 0:
        return "WEAK"
    return "STRONG"
