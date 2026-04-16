"""Discovery quality scoring for exploitation gating decisions."""

from typing import Dict


def score_discovery(metrics: Dict) -> Dict:
    endpoints = int(metrics.get("endpoints", 0) or 0)
    params = int(metrics.get("params", 0) or 0)
    api_calls = int(metrics.get("api_calls", 0) or 0)
    js_success = bool(metrics.get("js_success", False))
    source_signals = int(metrics.get("source_signals", 0) or 0)

    score = 0
    if endpoints >= 30:
        score += 45
    elif endpoints >= 20:
        score += 40
    elif endpoints >= 5:
        score += 30
    elif endpoints > 0:
        score += 20

    if params >= 20:
        score += 50
    elif params >= 15:
        score += 45
    elif params >= 5:
        score += 35
    elif params > 0:
        score += 25

    if api_calls >= 10:
        score += 15
    elif api_calls > 0:
        score += 8

    if source_signals >= 20:
        score += 10
    elif source_signals > 0:
        score += 5

    if js_success:
        score += 5

    if score >= 75:
        status = "STRONG"
    elif score >= 45:
        status = "ACCEPTABLE"
    else:
        status = "WEAK"

    # Only hard-abort when no meaningful attack surface exists.
    should_abort = endpoints == 0 and params == 0

    return {
        "score": score,
        "status": status,
        "should_abort_exploitation": should_abort,
    }
