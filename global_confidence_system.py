"""Global confidence scoring with reporting threshold enforcement."""

from typing import Dict


class GlobalConfidenceSystem:
    REPORT_THRESHOLD = 0.80

    @staticmethod
    def score(base_confidence: float, corroborated: bool = False, validated: bool = False, source: str = "internal") -> float:
        score = float(base_confidence or 0.0)
        if corroborated:
            score += 0.10
        if validated:
            score += 0.10
        if source == "zap":
            score += 0.03
        if source == "passive":
            score -= 0.05
        return max(0.0, min(1.0, score))

    @classmethod
    def should_report(cls, confidence: float) -> bool:
        return float(confidence or 0.0) >= cls.REPORT_THRESHOLD

    @classmethod
    def as_percentage(cls, confidence: float) -> int:
        return int(round(float(confidence or 0.0) * 100))
