"""Load the netexec_automator package so tests can import it as `nxa`.

The package's __init__.py re-exports everything top-level so the test
files don't need to know about the internal module layout (they continue
to use nxa.NxcAutomator / nxa.HASH_DUMP_LINE_RE / nxa._truncate_path /
nxa.NmapScanner._parse_xml exactly as before)."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def nxa():
    import netexec_automator as mod
    return mod
