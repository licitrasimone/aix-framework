"""
Smoke tests: every scanner can be instantiated and has required attributes.
Also verifies that load_payloads() returns non-empty lists.
"""

import pytest

from aix.modules.agent import AgentScanner
from aix.modules.dos import DoSScanner
from aix.modules.exfil import ExfilScanner
from aix.modules.extract import ExtractScanner
from aix.modules.fuzz import FuzzScanner
from aix.modules.inject import InjectScanner
from aix.modules.jailbreak import JailbreakScanner
from aix.modules.leak import LeakScanner
from aix.modules.memory import MemoryScanner
from aix.modules.rag import RAGScanner

SCANNER_CLASSES = [
    InjectScanner,
    JailbreakScanner,
    ExtractScanner,
    LeakScanner,
    ExfilScanner,
    AgentScanner,
    DoSScanner,
    FuzzScanner,
    MemoryScanner,
    RAGScanner,
]

# level/risk=5/3 ensures all payloads pass the filter
COMMON_KWARGS = {"quiet": True, "level": 5, "risk": 3}


def _get_payloads(scanner) -> list:
    """Return the scanner's loaded payload list regardless of attribute name."""
    for attr in ("default_payloads", "default_jailbreaks", "default_extractions", "default_probes"):
        val = getattr(scanner, attr, None)
        if val is not None:
            return val
    return []


@pytest.fixture(params=SCANNER_CLASSES, ids=lambda c: c.__name__)
def scanner(request):
    cls = request.param
    return cls(target="https://api.example.com", **COMMON_KWARGS)


class TestScannerInstantiation:
    def test_has_module_name(self, scanner):
        assert isinstance(scanner.module_name, str)
        assert len(scanner.module_name) > 0

    def test_has_console_color(self, scanner):
        assert hasattr(scanner, "console_color")

    def test_findings_starts_empty(self, scanner):
        assert scanner.findings == []

    def test_has_db(self, scanner):
        assert scanner.db is not None

    def test_has_target(self, scanner):
        assert scanner.target == "https://api.example.com"


class TestScannerPayloads:
    def test_default_payloads_non_empty(self, scanner):
        payloads = _get_payloads(scanner)
        assert len(payloads) > 0, f"{scanner.__class__.__name__} returned no payloads"

    def test_payloads_have_required_fields(self, scanner):
        for p in _get_payloads(scanner):
            assert "name" in p, f"Missing 'name' in {p}"
            assert "payload" in p, f"Missing 'payload' in {p}"
            assert "severity" in p, f"Missing 'severity' in {p}"

    def test_payloads_have_defaults_injected(self, scanner):
        for p in _get_payloads(scanner):
            assert "indicators" in p
            assert "category" in p
            assert "description" in p


class TestOutputAttribute:
    def test_output_none_by_default(self, scanner):
        assert scanner.output is None

    def test_output_set_from_kwarg(self):
        s = InjectScanner(
            target="https://api.example.com", quiet=True, output="/tmp/test.json"
        )
        assert s.output == "/tmp/test.json"
