"""Discovery quality scoring for exploitation gating decisions."""

from typing import Dict


def score_discovery(metrics: Dict) -> Dict:
    endpoints = int(metrics.get("endpoints", 0) or 0)
    params = int(metrics.get("params", 0) or 0)
    api_calls = int(metrics.get("api_calls", 0) or 0)
    js_success = bool(metrics.get("js_success", False))

    score = 0
    if endpoints >= 50:
        score += 30
    elif endpoints >= 20:
        score += 20
    elif endpoints > 0:
        score += 10

    if params >= 20:
        score += 30
    elif params >= 5:
        score += 20
    elif params > 0:
        score += 10

    if api_calls >= 10:
        score += 25
    elif api_calls > 0:
        score += 15

    if js_success:
        score += 15

    if score >= 80:
        status = "STRONG"
    elif score >= 50:
        status = "ACCEPTABLE"
    else:
        status = "WEAK"

    return {
        "score": score,
        "status": status,
        "should_abort_exploitation": status == "WEAK" and params == 0 and api_calls == 0,
    }
