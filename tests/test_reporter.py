"""
Tests for AIX Reporter Module
"""
import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from aix.core.reporter import Finding, Reporter, Severity


class TestSeverity:
    """Tests for Severity enum"""

    def test_severity_values(self):
        """Test all severity levels exist with correct values"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_ordering(self):
        """Test severity levels are distinct"""
        severities = [s.value for s in Severity]
        assert len(severities) == len(set(severities))  # All unique

    def test_severity_from_string(self):
        """Test creating severity from string"""
        assert Severity["CRITICAL"] == Severity.CRITICAL
        assert Severity["HIGH"] == Severity.HIGH
        assert Severity["MEDIUM"] == Severity.MEDIUM


class TestFinding:
    """Tests for Finding dataclass"""

    def test_finding_creation(self):
        """Test basic finding creation"""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            technique="injection",
            payload="test payload",
            response="test response",
            target="https://test.com"
        )

        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.technique == "injection"
        assert finding.payload == "test payload"
        assert finding.response == "test response"
        assert finding.target == "https://test.com"

    def test_finding_default_values(self):
        """Test finding with default values"""
        finding = Finding(
            title="Test",
            severity=Severity.LOW,
            technique="test",
            payload="payload",
            response="response"
        )

        assert finding.target == ""
        assert finding.details == ""
        assert finding.reason == ""
        assert isinstance(finding.timestamp, datetime)

    def test_finding_to_dict(self):
        """Test finding serialization to dict"""
        finding = Finding(
            title="Test Finding",
            severity=Severity.CRITICAL,
            technique="jailbreak",
            payload="DAN payload",
            response="I am DAN",
            target="https://api.example.com",
            details="Bypassed safety",
            reason="Model responded without restrictions"
        )

        result = finding.to_dict()

        assert result['title'] == "Test Finding"
        assert result['severity'] == "critical"
        assert result['technique'] == "jailbreak"
        assert result['payload'] == "DAN payload"
        assert result['response'] == "I am DAN"
        assert result['target'] == "https://api.example.com"
        assert result['details'] == "Bypassed safety"
        assert result['reason'] == "Model responded without restrictions"
        assert 'timestamp' in result

    def test_finding_timestamp_format(self):
        """Test timestamp is in ISO format"""
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            technique="test",
            payload="p",
            response="r"
        )

        result = finding.to_dict()
        # Should be valid ISO format
        datetime.fromisoformat(result['timestamp'])


class TestReporter:
    """Tests for Reporter class"""

    def test_reporter_initialization(self):
        """Test reporter initializes correctly"""
        reporter = Reporter()

        assert reporter.findings == []
        assert reporter.start_time is None
        assert reporter.end_time is None

    def test_reporter_start_end(self):
        """Test start/end time tracking"""
        reporter = Reporter()

        reporter.start()
        assert reporter.start_time is not None
        assert isinstance(reporter.start_time, datetime)

        reporter.end()
        assert reporter.end_time is not None
        assert reporter.end_time >= reporter.start_time

    def test_add_finding(self):
        """Test adding findings"""
        reporter = Reporter()
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            technique="test",
            payload="p",
            response="r"
        )

        reporter.add_finding(finding)

        assert len(reporter.findings) == 1
        assert reporter.findings[0] == finding

    def test_add_multiple_findings(self):
        """Test adding multiple findings"""
        reporter = Reporter()

        for i in range(5):
            finding = Finding(
                title=f"Finding {i}",
                severity=Severity.MEDIUM,
                technique="test",
                payload=f"payload_{i}",
                response=f"response_{i}"
            )
            reporter.add_finding(finding)

        assert len(reporter.findings) == 5

    def test_export_json(self):
        """Test JSON export"""
        reporter = Reporter()
        reporter.start()

        finding = Finding(
            title="JSON Export Test",
            severity=Severity.HIGH,
            technique="test",
            payload="test payload",
            response="test response",
            target="https://test.com"
        )
        reporter.add_finding(finding)
        reporter.end()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name

        try:
            reporter.export_json(filepath)

            with open(filepath) as f:
                data = json.load(f)

            assert 'scan_info' in data
            assert 'findings' in data
            assert data['scan_info']['total_findings'] == 1
            assert len(data['findings']) == 1
            assert data['findings'][0]['title'] == "JSON Export Test"
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_export_html(self):
        """Test HTML export"""
        reporter = Reporter()

        finding = Finding(
            title="HTML Export Test",
            severity=Severity.CRITICAL,
            technique="test",
            payload="<script>alert('xss')</script>",
            response="test response with <html>",
            target="https://test.com"
        )
        reporter.add_finding(finding)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)

            content = Path(filepath).read_text()

            assert '<!DOCTYPE html>' in content
            assert 'AIX Security Report' in content
            assert 'HTML Export Test' in content
            # Check HTML escaping
            assert '&lt;script&gt;' in content
            assert '<script>' not in content.split('<style>')[1].split('</style>')[0]  # Not in CSS
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_escape_html(self):
        """Test HTML escaping"""
        reporter = Reporter()

        test_cases = [
            ('&', '&amp;'),
            ('<', '&lt;'),
            ('>', '&gt;'),
            ('"', '&quot;'),
            ("'", '&#39;'),
            ('<script>alert("xss")</script>', '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'),
        ]

        for input_str, expected in test_cases:
            assert reporter._escape_html(input_str) == expected

    def test_export_json_empty(self):
        """Test JSON export with no findings"""
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name

        try:
            reporter.export_json(filepath)

            with open(filepath) as f:
                data = json.load(f)

            assert data['scan_info']['total_findings'] == 0
            assert data['findings'] == []
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_findings_by_severity(self):
        """Test findings are properly categorized by severity"""
        reporter = Reporter()

        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in severities:
            reporter.add_finding(Finding(
                title=f"{sev.value} finding",
                severity=sev,
                technique="test",
                payload="p",
                response="r"
            ))

        # Verify all severities present
        found_severities = {f.severity for f in reporter.findings}
        assert found_severities == set(severities)
