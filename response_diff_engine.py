"""
Compatibility wrapper for response diffing engine.
Provides requested module name: response_diff_engine.py
"""

from response_diffing_engine import (
    DiffingStrategy,
    DiffResult,
    HTTPResponse,
    ResponseDiffingEngine,
)

__all__ = [
    "ResponseDiffingEngine",
    "HTTPResponse",
    "DiffResult",
    "DiffingStrategy",
]
