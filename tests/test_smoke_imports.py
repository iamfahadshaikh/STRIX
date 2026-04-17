import importlib

MODULES = [
    "automation_scanner_v2",
    "decision_ledger",
    "target_profile",
    "cache_discovery",
    "tool_manager",
    "tool_parsers",
    "intelligence_layer",
    "findings_model",
    "risk_engine",
    "html_report_generator",
]


def test_smoke_imports():
    for module_name in MODULES:
        importlib.import_module(module_name)
