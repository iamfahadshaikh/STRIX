"""
Compatibility wrapper for service fingerprinting engine.
Provides requested module name: service_fingerprinter.py
"""

from service_fingerprinting_engine import (
    ServiceFingerprint,
    ServiceFingerprintingEngine,
)

__all__ = [
    "ServiceFingerprintingEngine",
    "ServiceFingerprint",
]
