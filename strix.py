#!/usr/bin/env python3
"""
STRIX - Precision-driven VAPT orchestration engine

Entry point for the STRIX security testing framework.
Run: python strix.py <target> [options]
Or:  pip install -e . && strix <target> [options]
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Import main function from automation_scanner_v2
from automation_scanner_v2 import main


if __name__ == "__main__":
    main()
