"""Load the single-file tool as a module so tests can import it.

The tool ships as `netexec-automator.py` (with a dash, no package).
importlib lets us pull it in as `nxa` without renaming or restructuring."""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def nxa():
    spec = importlib.util.spec_from_file_location(
        "nxa", REPO_ROOT / "netexec-automator.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["nxa"] = mod
    spec.loader.exec_module(mod)
    return mod
