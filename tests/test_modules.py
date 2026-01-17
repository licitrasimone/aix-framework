"""
Tests for AIX Attack Modules
"""
import pytest

from aix.core.reporter import Severity


class TestModuleImports:
    """Tests for module imports"""

    def test_import_inject(self):
        """Test inject module imports"""
        from aix.modules import inject
        assert hasattr(inject, 'run')
        assert hasattr(inject, 'InjectScanner')

    def test_import_jailbreak(self):
        """Test jailbreak module imports"""
        from aix.modules import jailbreak
        assert hasattr(jailbreak, 'run')
        assert hasattr(jailbreak, 'JailbreakScanner')

    def test_import_extract(self):
        """Test extract module imports"""
        from aix.modules import extract
        assert hasattr(extract, 'run')
        assert hasattr(extract, 'ExtractScanner')

    def test_import_leak(self):
        """Test leak module imports"""
        from aix.modules import leak
        assert hasattr(leak, 'run')
        assert hasattr(leak, 'LeakScanner')

    def test_import_exfil(self):
        """Test exfil module imports"""
        from aix.modules import exfil
        assert hasattr(exfil, 'run')
        assert hasattr(exfil, 'ExfilScanner')

    def test_import_agent(self):
        """Test agent module imports"""
        from aix.modules import agent
        assert hasattr(agent, 'run')
        assert hasattr(agent, 'AgentScanner')

    def test_import_dos(self):
        """Test dos module imports"""
        from aix.modules import dos
        assert hasattr(dos, 'run')
        assert hasattr(dos, 'DoSScanner')

    def test_import_fuzz(self):
        """Test fuzz module imports"""
        from aix.modules import fuzz
        assert hasattr(fuzz, 'run')
        assert hasattr(fuzz, 'FuzzScanner')

    def test_import_recon(self):
        """Test recon module imports"""
        from aix.modules import recon
        assert hasattr(recon, 'run')
        assert hasattr(recon, 'ReconScanner')


class TestInjectScanner:
    """Tests for InjectScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://api.example.com",
            api_key="test-key",
            verbose=1
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.api_key == "test-key"
        assert scanner.verbose == 1
        assert scanner.module_name == "INJECT"

    def test_scanner_loads_payloads(self):
        """Test scanner loads payloads"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            level=5,
            risk=3
        )

        # Should load payloads (may be filtered by default_payloads attribute)
        assert hasattr(scanner, 'payloads') or hasattr(scanner, 'default_payloads')

    def test_scanner_filters_by_level(self):
        """Test scanner filters payloads by level"""
        from aix.modules.inject import InjectScanner

        scanner_low = InjectScanner(
            target="https://example.com",
            level=1,
            risk=1
        )

        scanner_high = InjectScanner(
            target="https://example.com",
            level=5,
            risk=3
        )

        # Higher level should have more or equal payloads
        assert len(scanner_high.payloads) >= len(scanner_low.payloads)


class TestJailbreakScanner:
    """Tests for JailbreakScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.jailbreak import JailbreakScanner

        scanner = JailbreakScanner(
            target="https://api.example.com",
            verbose=0
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.module_name == "JAILBRK"

    def test_scanner_has_payloads(self):
        """Test scanner has jailbreak payloads"""
        from aix.modules.jailbreak import JailbreakScanner

        scanner = JailbreakScanner(
            target="https://example.com",
            level=5,
            risk=3
        )

        # Should have payloads or default_jailbreaks
        assert hasattr(scanner, 'payloads') or hasattr(scanner, 'default_jailbreaks')


class TestExtractScanner:
    """Tests for ExtractScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.extract import ExtractScanner

        scanner = ExtractScanner(
            target="https://api.example.com"
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.module_name == "EXTRACT"


class TestDoSScanner:
    """Tests for DoSScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.dos import DoSScanner

        scanner = DoSScanner(
            target="https://api.example.com"
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.module_name == "DOS"


class TestFuzzScanner:
    """Tests for FuzzScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.fuzz import FuzzScanner

        scanner = FuzzScanner(
            target="https://api.example.com",
            iterations=50
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.module_name == "FUZZ"
        assert scanner.iterations == 50


class TestReconScanner:
    """Tests for ReconScanner"""

    def test_scanner_init(self):
        """Test scanner initialization"""
        from aix.modules.recon import ReconScanner

        scanner = ReconScanner(
            target="https://api.example.com"
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.module_name == "RECON"

    def test_scanner_has_config(self):
        """Test scanner loads config"""
        from aix.modules.recon import ReconScanner

        scanner = ReconScanner(
            target="https://example.com"
        )

        # Should have config with model signatures
        assert hasattr(scanner, 'config')
        assert 'model_signatures' in scanner.config or scanner.config == {}


class TestBaseScannerInheritance:
    """Tests for BaseScanner inheritance"""

    def test_all_scanners_have_run_method(self):
        """Test all scanners have run method"""
        from aix.modules.inject import InjectScanner
        from aix.modules.jailbreak import JailbreakScanner
        from aix.modules.extract import ExtractScanner
        from aix.modules.leak import LeakScanner
        from aix.modules.dos import DoSScanner
        from aix.modules.fuzz import FuzzScanner
        from aix.modules.recon import ReconScanner

        scanners = [
            InjectScanner("https://example.com"),
            JailbreakScanner("https://example.com"),
            ExtractScanner("https://example.com"),
            LeakScanner("https://example.com"),
            DoSScanner("https://example.com"),
            FuzzScanner("https://example.com"),
            ReconScanner("https://example.com"),
        ]

        for scanner in scanners:
            assert hasattr(scanner, 'run')
            assert callable(scanner.run)

    def test_all_scanners_have_stats(self):
        """Test all scanners have stats dict"""
        from aix.modules.inject import InjectScanner
        from aix.modules.jailbreak import JailbreakScanner

        scanners = [
            InjectScanner("https://example.com"),
            JailbreakScanner("https://example.com"),
        ]

        for scanner in scanners:
            assert hasattr(scanner, 'stats')
            assert isinstance(scanner.stats, dict)

    def test_all_scanners_have_findings(self):
        """Test all scanners have findings list"""
        from aix.modules.inject import InjectScanner
        from aix.modules.jailbreak import JailbreakScanner

        scanners = [
            InjectScanner("https://example.com"),
            JailbreakScanner("https://example.com"),
        ]

        for scanner in scanners:
            assert hasattr(scanner, 'findings')
            assert isinstance(scanner.findings, list)


class TestScannerPayloadFiltering:
    """Tests for payload filtering by level and risk"""

    def test_level_filtering(self):
        """Test payloads are filtered by level"""
        from aix.modules.inject import InjectScanner

        # Level 1 should have fewer payloads
        scanner_l1 = InjectScanner("https://example.com", level=1, risk=3)
        scanner_l5 = InjectScanner("https://example.com", level=5, risk=3)

        # All level-1 payloads should be included at level 5
        assert len(scanner_l5.payloads) >= len(scanner_l1.payloads)

    def test_risk_filtering(self):
        """Test payloads are filtered by risk"""
        from aix.modules.inject import InjectScanner

        # Risk 1 should have fewer payloads
        scanner_r1 = InjectScanner("https://example.com", level=5, risk=1)
        scanner_r3 = InjectScanner("https://example.com", level=5, risk=3)

        # All risk-1 payloads should be included at risk 3
        assert len(scanner_r3.payloads) >= len(scanner_r1.payloads)


class TestScannerConnectorCreation:
    """Tests for connector creation"""

    def test_creates_api_connector_for_url(self):
        """Test API connector is created for URL target"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://api.example.com",
            api_key="test-key"
        )

        connector = scanner._create_connector()

        from aix.core.connector import APIConnector
        assert isinstance(connector, APIConnector)

    def test_creates_request_connector_for_parsed_request(self):
        """Test Request connector is created for parsed request"""
        from aix.modules.inject import InjectScanner
        from aix.core.request_parser import ParsedRequest

        request = ParsedRequest(
            method="POST",
            url="https://example.com/api",
            headers={"Content-Type": "application/json"},
            body='{"message": "test"}',
            body_json={"message": "test"},
            injection_param="message"
        )

        scanner = InjectScanner(
            target="https://example.com",
            parsed_request=request
        )

        connector = scanner._create_connector()

        from aix.core.connector import RequestConnector
        assert isinstance(connector, RequestConnector)
