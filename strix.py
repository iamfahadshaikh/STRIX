#!/usr/bin/env python3
"""
STRIX - Precision-driven VAPT orchestration engine

Entry point for the STRIX security testing framework.
Run: python strix.py <target> [options]
Or:  pip install -e . && strix <target> [options]
"""

# Import main function from automation_scanner_v2
from automation_scanner_v2 import main


if __name__ == "__main__":
    main()
