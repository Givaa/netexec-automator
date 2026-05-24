#!/usr/bin/env python3
"""Thin launcher — the actual code lives in the netexec_automator/ package.

Kept as a single dashed-name script so the existing CLI invocation
`python3 netexec-automator.py …` keeps working exactly as before."""

import os
import sys
from pathlib import Path

# Make the sibling package importable when the script is invoked directly
# from any cwd (e.g. `python3 /opt/.../netexec-automator.py …`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from netexec_automator.cli import main

if __name__ == "__main__":
    main()
