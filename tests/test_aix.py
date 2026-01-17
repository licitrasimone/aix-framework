"""
AIX Core Tests - Basic Functionality Tests
"""
import os
import tempfile

import pytest

from aix import __version__


class TestVersion:
    """Tests for version information"""

    def test_version_is_set(self):
        """Test version is set correctly"""
        assert __version__ == "1.0.0"

    def test_version_format(self):
        """Test version follows semver format"""
        parts = __version__.split('.')
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


class TestAPIConnector:
    """Tests for API Connector"""

    @pytest.mark.asyncio
    async def test_api_connector_init(self):
        """Test API connector initialization"""
        from aix.core.connector import APIConnector

        connector = APIConnector(
            url="https://api.openai.com",
            api_key="test-key"
        )

        assert connector.url == "https://api.openai.com"
        assert connector.api_key == "test-key"

    @pytest.mark.asyncio
    async def test_api_connector_with_options(self):
        """Test API connector with various options"""
        from aix.core.connector import APIConnector

        connector = APIConnector(
            url="https://api.example.com",
            api_key="key",
            proxy="127.0.0.1:8080",
            timeout=60,
            verbose=2
        )

        # Options are stored in config dict
        assert connector.config.get('proxy') == "127.0.0.1:8080"
        assert connector.config.get('timeout') == 60
        assert connector.config.get('verbose') == 2


class TestDatabase:
    """Tests for Database"""

    def test_database_init(self):
        """Test database initialization"""
        from aix.db.database import AIXDatabase

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            # Test adding result
            result_id = db.add_result(
                target="https://test.com",
                module="inject",
                technique="test_technique",
                result="success",
                payload="test payload",
                response="test response",
                severity="high"
            )

            assert result_id > 0

            # Test retrieving results
            results = db.get_results(target="test.com")
            assert len(results) == 1
            assert results[0]['technique'] == "test_technique"

            db.close()

    def test_database_clear(self):
        """Test database clear functionality"""
        from aix.db.database import AIXDatabase

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            # Add some results
            for i in range(5):
                db.add_result(
                    target="https://test.com",
                    module="test",
                    technique=f"tech_{i}",
                    result="success",
                    payload="p",
                    response="r",
                    severity="low"
                )

            assert len(db.get_results()) == 5

            db.clear()

            assert len(db.get_results()) == 0

            db.close()


class TestReporter:
    """Tests for Reporter"""

    def test_reporter_init(self):
        """Test reporter functionality"""
        from aix.core.reporter import Finding, Reporter, Severity

        reporter = Reporter()

        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            technique="test",
            payload="test payload",
            response="test response",
            target="https://test.com"
        )

        reporter.add_finding(finding)

        assert len(reporter.findings) == 1
        assert reporter.findings[0].severity == Severity.HIGH

    def test_reporter_severity_levels(self):
        """Test all severity levels"""
        from aix.core.reporter import Finding, Reporter, Severity

        reporter = Reporter()

        for severity in Severity:
            finding = Finding(
                title=f"{severity.value} Finding",
                severity=severity,
                technique="test",
                payload="p",
                response="r"
            )
            reporter.add_finding(finding)

        assert len(reporter.findings) == 5  # 5 severity levels


class TestModuleImports:
    """Test all modules can be imported"""

    def test_import_main_module(self):
        """Test main aix module imports"""
        import aix
        assert hasattr(aix, '__version__')

    def test_import_core_modules(self):
        """Test core modules import"""
        from aix.core import connector, reporter, scanner
        assert connector is not None
        assert reporter is not None
        assert scanner is not None

    def test_import_attack_modules(self):
        """Test attack modules import"""
        from aix.modules import (
            inject, jailbreak, extract, leak,
            exfil, agent, dos, fuzz, recon
        )
        assert inject is not None
        assert jailbreak is not None
        assert extract is not None
        assert leak is not None
        assert exfil is not None
        assert agent is not None
        assert dos is not None
        assert fuzz is not None
        assert recon is not None


class TestRequestParser:
    """Tests for Request Parser"""

    def test_parse_simple_request(self):
        """Test parsing simple HTTP request"""
        from aix.core.request_parser import RequestParser

        content = """POST /api/chat HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"message": "hello"}"""

        request = RequestParser.parse_raw(content)

        assert request.method == "POST"
        assert "api.example.com" in request.url
        assert request.body_json is not None
        assert request.body_json["message"] == "hello"

    def test_nested_value_operations(self):
        """Test nested value get/set operations"""
        from aix.core.request_parser import get_nested_value, set_nested_value

        obj = {"messages": [{"role": "user", "content": "hello"}]}

        # Test get
        assert get_nested_value(obj, "messages[0].content") == "hello"

        # Test set
        result = set_nested_value(obj, "messages[0].content", "modified")
        assert result["messages"][0]["content"] == "modified"
        assert obj["messages"][0]["content"] == "hello"  # Original unchanged
