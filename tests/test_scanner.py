"""
Tests for AIX Base Scanner Module
"""
import pytest

from aix.core.scanner import BaseScanner, TargetProfile, AttackResult, AttackResponse


class TestBaseScanner:
    """Tests for BaseScanner class"""

    def test_init_basic(self):
        """Test basic initialization"""
        # BaseScanner is abstract but we can test through a subclass
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://api.example.com",
            api_key="test-key"
        )

        assert scanner.target == "https://api.example.com"
        assert scanner.api_key == "test-key"

    def test_init_with_verbose(self):
        """Test initialization with verbose levels"""
        from aix.modules.inject import InjectScanner

        for level in [0, 1, 2, 3]:
            scanner = InjectScanner(
                target="https://example.com",
                verbose=level
            )
            assert scanner.verbose == level

    def test_init_with_proxy(self):
        """Test initialization with proxy"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            proxy="127.0.0.1:8080"
        )

        assert scanner.proxy == "127.0.0.1:8080"

    def test_init_with_cookies(self):
        """Test initialization with cookies"""
        from aix.modules.inject import InjectScanner

        cookies = {"session": "abc123", "token": "xyz"}
        scanner = InjectScanner(
            target="https://example.com",
            cookies=cookies
        )

        assert scanner.cookies == cookies

    def test_init_with_headers(self):
        """Test initialization with custom headers"""
        from aix.modules.inject import InjectScanner

        headers = {"X-Custom": "value", "Authorization": "Bearer token"}
        scanner = InjectScanner(
            target="https://example.com",
            headers=headers
        )

        assert scanner.headers == headers

    def test_init_with_level_risk(self):
        """Test initialization with level and risk"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            level=3,
            risk=2
        )

        assert scanner.level == 3
        assert scanner.risk == 2

    def test_init_default_level_risk(self):
        """Test default level and risk values"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.level == 1
        assert scanner.risk == 1

    def test_init_with_timeout(self):
        """Test initialization with timeout"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            timeout=60
        )

        assert scanner.timeout == 60

    def test_init_default_timeout(self):
        """Test default timeout"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.timeout == 30

    def test_stats_initialization(self):
        """Test stats dict is initialized"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert 'total' in scanner.stats
        assert 'success' in scanner.stats
        assert 'blocked' in scanner.stats
        assert scanner.stats['total'] == 0
        assert scanner.stats['success'] == 0
        assert scanner.stats['blocked'] == 0

    def test_findings_initialization(self):
        """Test findings list is initialized"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert isinstance(scanner.findings, list)
        assert len(scanner.findings) == 0

    def test_database_initialization(self):
        """Test database is initialized"""
        from aix.modules.inject import InjectScanner
        from aix.db.database import AIXDatabase

        scanner = InjectScanner(target="https://example.com")

        assert hasattr(scanner, 'db')
        assert isinstance(scanner.db, AIXDatabase)


class TestTargetProfile:
    """Tests for TargetProfile class"""

    def test_init(self):
        """Test TargetProfile initialization"""
        profile = TargetProfile("https://api.example.com")

        assert profile.target == "https://api.example.com"


class TestAttackResult:
    """Tests for AttackResult class"""

    def test_success_result(self):
        """Test successful attack result"""
        result = AttackResult(success=True, data={"response": "vulnerable"})

        assert result.success is True
        assert result.data == {"response": "vulnerable"}

    def test_failure_result(self):
        """Test failed attack result"""
        result = AttackResult(success=False)

        assert result.success is False
        assert result.data is None


class TestAttackResponse:
    """Tests for AttackResponse class"""

    def test_response(self):
        """Test AttackResponse initialization"""
        response = AttackResponse("Model responded with sensitive data")

        assert response.response == "Model responded with sensitive data"


class TestScannerPayloadLoading:
    """Tests for payload loading functionality"""

    def test_load_payloads_returns_list(self):
        """Test load_payloads returns a list"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")
        payloads = scanner.load_payloads("inject.json")

        assert isinstance(payloads, list)

    def test_load_payloads_filters_by_level(self):
        """Test payloads are filtered by level"""
        from aix.modules.inject import InjectScanner

        scanner_low = InjectScanner(target="https://example.com", level=1, risk=3)
        scanner_high = InjectScanner(target="https://example.com", level=5, risk=3)

        payloads_low = scanner_low.load_payloads("inject.json")
        payloads_high = scanner_high.load_payloads("inject.json")

        assert len(payloads_high) >= len(payloads_low)

    def test_load_payloads_reconstructs_severity(self):
        """Test severity strings are converted to enums"""
        from aix.modules.inject import InjectScanner
        from aix.core.reporter import Severity

        scanner = InjectScanner(target="https://example.com", level=5, risk=3)
        payloads = scanner.load_payloads("inject.json")

        for payload in payloads:
            if 'severity' in payload:
                assert isinstance(payload['severity'], Severity)

    def test_load_nonexistent_payloads(self):
        """Test loading non-existent payload file"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")
        payloads = scanner.load_payloads("nonexistent.json")

        # Should return empty list, not raise
        assert payloads == []


class TestScannerConnectorCreation:
    """Tests for _create_connector method"""

    def test_create_api_connector(self):
        """Test creating API connector"""
        from aix.modules.inject import InjectScanner
        from aix.core.connector import APIConnector

        scanner = InjectScanner(
            target="https://api.example.com",
            api_key="test-key"
        )

        connector = scanner._create_connector()

        assert isinstance(connector, APIConnector)

    def test_create_request_connector(self):
        """Test creating Request connector"""
        from aix.modules.inject import InjectScanner
        from aix.core.connector import RequestConnector
        from aix.core.request_parser import ParsedRequest

        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={},
            injection_param="message"
        )

        scanner = InjectScanner(
            target="https://example.com",
            parsed_request=request
        )

        connector = scanner._create_connector()

        assert isinstance(connector, RequestConnector)

    def test_connector_inherits_proxy(self):
        """Test connector inherits proxy setting"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            proxy="127.0.0.1:8080"
        )

        connector = scanner._create_connector()

        # Proxy is stored in config
        assert connector.config.get('proxy') == "127.0.0.1:8080"

    def test_connector_inherits_timeout(self):
        """Test connector inherits timeout"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com",
            timeout=120
        )

        connector = scanner._create_connector()

        # Timeout is stored in config
        assert connector.config.get('timeout') == 120


class TestScannerEvaluator:
    """Tests for evaluator integration"""

    def test_no_evaluator_by_default(self):
        """Test no evaluator is created by default"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.evaluator is None

    def test_evaluator_created_with_config(self):
        """Test evaluator is created when config provided"""
        from aix.modules.inject import InjectScanner

        eval_config = {
            'provider': 'openai',
            'api_key': 'test-key',
            'model': 'gpt-4'
        }

        scanner = InjectScanner(
            target="https://example.com",
            eval_config=eval_config
        )

        assert scanner.evaluator is not None


class TestScannerCheckSuccess:
    """Tests for check_success method"""

    @pytest.mark.asyncio
    async def test_check_success_with_indicators(self):
        """Test success detection with indicators"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        response = "I will ignore my previous instructions"
        indicators = ["ignore", "previous instructions"]

        result = await scanner.check_success(
            response=response,
            indicators=indicators,
            payload="test",
            technique="test"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_check_success_no_match(self):
        """Test success detection with no matching indicators"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        response = "I cannot help with that request"
        indicators = ["vulnerable", "hacked"]

        result = await scanner.check_success(
            response=response,
            indicators=indicators,
            payload="test",
            technique="test"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_check_success_case_insensitive(self):
        """Test indicator matching is case insensitive"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        response = "I AM VULNERABLE NOW"
        indicators = ["vulnerable"]

        result = await scanner.check_success(
            response=response,
            indicators=indicators,
            payload="test",
            technique="test"
        )

        assert result is True
