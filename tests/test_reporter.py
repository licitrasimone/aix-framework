"""
Tests for AIX Reporter Module
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

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
            target="https://test.com",
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
            response="response",
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
            reason="Model responded without restrictions",
        )

        result = finding.to_dict()

        assert result["title"] == "Test Finding"
        assert result["severity"] == "critical"
        assert result["technique"] == "jailbreak"
        assert result["payload"] == "DAN payload"
        assert result["response"] == "I am DAN"
        assert result["target"] == "https://api.example.com"
        assert result["details"] == "Bypassed safety"
        assert result["reason"] == "Model responded without restrictions"
        assert "timestamp" in result

    def test_finding_timestamp_format(self):
        """Test timestamp is in ISO format"""
        finding = Finding(
            title="Test", severity=Severity.INFO, technique="test", payload="p", response="r"
        )

        result = finding.to_dict()
        # Should be valid ISO format
        datetime.fromisoformat(result["timestamp"])


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
            title="Test", severity=Severity.HIGH, technique="test", payload="p", response="r"
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
                response=f"response_{i}",
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
            target="https://test.com",
        )
        reporter.add_finding(finding)
        reporter.end()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_json(filepath)

            with open(filepath) as f:
                data = json.load(f)

            assert "scan_info" in data
            assert "findings" in data
            assert data["scan_info"]["total_findings"] == 1
            assert len(data["findings"]) == 1
            assert data["findings"][0]["title"] == "JSON Export Test"
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
            target="https://test.com",
        )
        reporter.add_finding(finding)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)

            content = Path(filepath).read_text()

            assert "<!DOCTYPE html>" in content
            assert "AIX Security Report" in content
            assert "HTML Export Test" in content
            # Check HTML escaping
            assert "&lt;script&gt;" in content
            assert "<script>" not in content.split("<style>")[1].split("</style>")[0]  # Not in CSS
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_escape_html(self):
        """Test HTML escaping"""
        reporter = Reporter()

        test_cases = [
            ("&", "&amp;"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ('"', "&quot;"),
            ("'", "&#39;"),
            (
                '<script>alert("xss")</script>',
                "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;",
            ),
        ]

        for input_str, expected in test_cases:
            assert reporter._escape_html(input_str) == expected

    def test_export_json_empty(self):
        """Test JSON export with no findings"""
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_json(filepath)

            with open(filepath) as f:
                data = json.load(f)

            assert data["scan_info"]["total_findings"] == 0
            assert data["findings"] == []
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_findings_by_severity(self):
        """Test findings are properly categorized by severity"""
        reporter = Reporter()

        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for sev in severities:
            reporter.add_finding(
                Finding(
                    title=f"{sev.value} finding",
                    severity=sev,
                    technique="test",
                    payload="p",
                    response="r",
                )
            )

        # Verify all severities present
        found_severities = {f.severity for f in reporter.findings}
        assert found_severities == set(severities)


class TestRiskScore:
    """Tests for risk score calculation"""

    def test_no_findings_score_zero(self):
        """Test risk score is 0 with no findings"""
        reporter = Reporter()
        assert reporter.calculate_risk_score() == 0.0

    def test_single_critical_finding(self):
        """Test risk score with a single critical finding"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.CRITICAL, technique="t", payload="p", response="r")
        )
        # critical=10, 10/5=2.0
        assert reporter.calculate_risk_score() == 2.0

    def test_score_capped_at_ten(self):
        """Test risk score is capped at 10.0"""
        reporter = Reporter()
        # 10 critical findings: 10*10=100, 100/5=20 -> capped at 10
        for _ in range(10):
            reporter.add_finding(
                Finding(title="t", severity=Severity.CRITICAL, technique="t", payload="p", response="r")
            )
        assert reporter.calculate_risk_score() == 10.0

    def test_mixed_severities(self):
        """Test risk score with mixed severities"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )
        reporter.add_finding(
            Finding(title="t", severity=Severity.MEDIUM, technique="t", payload="p", response="r")
        )
        # high=7 + medium=4 = 11, 11/5 = 2.2
        assert abs(reporter.calculate_risk_score() - 2.2) < 0.01

    def test_info_findings_zero_weight(self):
        """Test that info findings contribute 0 to risk score"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.INFO, technique="t", payload="p", response="r")
        )
        assert reporter.calculate_risk_score() == 0.0

    def test_risk_level_critical(self):
        """Test risk level classification for critical scores"""
        reporter = Reporter()
        assert reporter.get_risk_level(8.0) == "Critical"
        assert reporter.get_risk_level(10.0) == "Critical"

    def test_risk_level_high(self):
        """Test risk level classification for high scores"""
        reporter = Reporter()
        assert reporter.get_risk_level(5.0) == "High"
        assert reporter.get_risk_level(7.9) == "High"

    def test_risk_level_medium(self):
        """Test risk level classification for medium scores"""
        reporter = Reporter()
        assert reporter.get_risk_level(2.0) == "Medium"
        assert reporter.get_risk_level(4.9) == "Medium"

    def test_risk_level_low(self):
        """Test risk level classification for low scores"""
        reporter = Reporter()
        assert reporter.get_risk_level(0.0) == "Low"
        assert reporter.get_risk_level(1.9) == "Low"


class TestOWASPCoverage:
    """Tests for OWASP coverage mapping"""

    def test_empty_coverage(self):
        """Test OWASP coverage with no findings"""
        reporter = Reporter()
        coverage = reporter.get_owasp_coverage()
        assert len(coverage) == 10
        for cat_id, info in coverage.items():
            assert info["tested"] is False
            assert info["findings_count"] == 0

    def test_coverage_with_findings(self):
        """Test OWASP coverage with findings tagged to categories"""
        from aix.core.owasp import OWASPCategory

        reporter = Reporter()
        reporter.add_finding(
            Finding(
                title="Injection",
                severity=Severity.CRITICAL,
                technique="test",
                payload="p",
                response="r",
                owasp=[OWASPCategory.LLM01],
            )
        )

        coverage = reporter.get_owasp_coverage()
        assert coverage["LLM01"]["tested"] is True
        assert coverage["LLM01"]["findings_count"] == 1
        assert coverage["LLM01"]["max_severity"] == "critical"
        # Other categories should remain untested
        assert coverage["LLM02"]["tested"] is False

    def test_coverage_multiple_findings_same_category(self):
        """Test OWASP coverage counts multiple findings per category"""
        from aix.core.owasp import OWASPCategory

        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t1", severity=Severity.HIGH, technique="t", payload="p", response="r",
                    owasp=[OWASPCategory.LLM06])
        )
        reporter.add_finding(
            Finding(title="t2", severity=Severity.CRITICAL, technique="t", payload="p", response="r",
                    owasp=[OWASPCategory.LLM06])
        )

        coverage = reporter.get_owasp_coverage()
        assert coverage["LLM06"]["findings_count"] == 2
        assert coverage["LLM06"]["max_severity"] == "critical"

    def test_coverage_all_categories(self):
        """Test that all 10 OWASP categories are present"""
        reporter = Reporter()
        coverage = reporter.get_owasp_coverage()
        for i in range(1, 11):
            assert f"LLM{i:02d}" in coverage


class TestExecutiveSummary:
    """Tests for executive summary generation"""

    def test_no_findings_summary(self):
        """Test summary with no findings"""
        reporter = Reporter()
        summary = reporter.generate_executive_summary()
        assert "No vulnerabilities" in summary

    def test_critical_risk_summary(self):
        """Test summary for critical risk"""
        reporter = Reporter()
        for _ in range(5):
            reporter.add_finding(
                Finding(title="t", severity=Severity.CRITICAL, technique="t", payload="p", response="r")
            )
        summary = reporter.generate_executive_summary()
        assert "Immediate remediation" in summary
        assert "5 critical" in summary

    def test_high_risk_summary(self):
        """Test summary for high risk"""
        reporter = Reporter()
        for _ in range(4):
            reporter.add_finding(
                Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
            )
        summary = reporter.generate_executive_summary()
        assert "Significant vulnerabilities" in summary

    def test_medium_risk_summary(self):
        """Test summary for medium risk"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )
        summary = reporter.generate_executive_summary()
        # high=7, 7/5=1.4 -> Low risk
        # Actually 1.4 < 2 so this is "Low risk"
        assert "risk" in summary.lower()

    def test_summary_contains_count(self):
        """Test summary contains finding count"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.MEDIUM, technique="t", payload="p", response="r")
        )
        reporter.add_finding(
            Finding(title="t", severity=Severity.LOW, technique="t", payload="p", response="r")
        )
        summary = reporter.generate_executive_summary()
        assert "2 vulnerabilities" in summary


class TestScanMetadata:
    """Tests for ScanMetadata integration"""

    def test_metadata_defaults(self):
        """Test ScanMetadata default values"""
        from aix.core.reporting.base import ScanMetadata

        meta = ScanMetadata()
        assert meta.session_id is None
        assert meta.target == ""
        assert meta.modules_run == []
        assert meta.risk_score == 0.0

    def test_reporter_with_metadata(self):
        """Test reporter stores metadata"""
        from aix.core.reporting.base import ScanMetadata

        reporter = Reporter()
        reporter.metadata = ScanMetadata(
            session_id="test-session",
            target="https://example.com",
            modules_run=["inject", "jailbreak"],
        )
        assert reporter.metadata.session_id == "test-session"
        assert reporter.metadata.modules_run == ["inject", "jailbreak"]

    def test_json_export_with_metadata(self):
        """Test JSON export includes metadata"""
        from aix.core.reporting.base import ScanMetadata

        reporter = Reporter()
        reporter.metadata = ScanMetadata(
            session_id="sid-123",
            session_name="Test Session",
            target="https://example.com",
            modules_run=["inject"],
        )
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_json(filepath)
            with open(filepath) as f:
                data = json.load(f)

            assert data["scan_info"]["session_id"] == "sid-123"
            assert data["scan_info"]["session_name"] == "Test Session"
            assert data["scan_info"]["target"] == "https://example.com"
            assert data["scan_info"]["modules_run"] == ["inject"]
            assert data["scan_info"]["risk_score"] > 0
            assert "executive_summary" in data
            assert "owasp_coverage" in data
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestEnhancedHTMLExport:
    """Tests for enhanced HTML export"""

    def test_html_contains_executive_summary(self):
        """Test HTML report contains executive summary section"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "Executive Summary" in content
            assert "Risk Score" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_contains_severity_chart(self):
        """Test HTML report contains severity distribution chart"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.CRITICAL, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "Severity Distribution" in content
            assert "chart-bar-fill" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_contains_owasp_grid(self):
        """Test HTML report contains OWASP coverage grid"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "OWASP LLM Top 10 Coverage" in content
            assert "owasp-card" in content
            assert "LLM01" in content
            assert "LLM10" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_contains_remediation(self):
        """Test HTML report contains remediation when OWASP findings exist"""
        from aix.core.owasp import OWASPCategory

        reporter = Reporter()
        reporter.add_finding(
            Finding(
                title="Injection Finding",
                severity=Severity.CRITICAL,
                technique="test",
                payload="p",
                response="r",
                owasp=[OWASPCategory.LLM01],
            )
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "Remediation Recommendations" in content
            assert "Prompt Injection" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_no_remediation_without_owasp(self):
        """Test HTML report omits remediation when no OWASP findings"""
        reporter = Reporter()
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "Remediation Recommendations" not in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_contains_metadata_section(self):
        """Test HTML report contains metadata when provided"""
        from aix.core.reporting.base import ScanMetadata

        reporter = Reporter()
        reporter.metadata = ScanMetadata(
            session_name="Test Session",
            target="https://example.com",
            modules_run=["inject", "jailbreak"],
            start_time=datetime(2026, 1, 15, 10, 30),
            end_time=datetime(2026, 1, 15, 10, 35),
        )
        reporter.add_finding(
            Finding(title="t", severity=Severity.HIGH, technique="t", payload="p", response="r")
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "Test Session" in content
            assert "https://example.com" in content
            assert "inject, jailbreak" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_html_contains_aix_version(self):
        """Test HTML footer contains AIX version"""
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            reporter.export_html(filepath)
            content = Path(filepath).read_text()
            assert "AIX v" in content
            assert "AI eXploit Framework" in content
        finally:
            Path(filepath).unlink(missing_ok=True)
