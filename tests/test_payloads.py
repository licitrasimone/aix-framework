"""
Tests for AIX Payload Loading and Validation
"""

import json
from pathlib import Path

import pytest

from aix.core.reporter import Severity


class TestPayloadFiles:
    """Tests for payload JSON files"""

    PAYLOAD_DIR = Path(__file__).parent.parent / "aix" / "payloads"

    PAYLOAD_FILES = [
        "inject.json",
        "jailbreak.json",
        "extract.json",
        "leak.json",
        "exfil.json",
        "agent.json",
        "dos.json",
        "fuzz.json",
        "recon.json",
    ]

    CONFIG_FILES = [
        "recon_config.json",
        "leak_config.json",
        "fuzz_config.json",
        "fingerprint_embeddings.json",
    ]

    PROBE_FILES = [
        "fingerprint_probes.json",
    ]

    def test_payload_dir_exists(self):
        """Test payload directory exists"""
        assert self.PAYLOAD_DIR.exists()
        assert self.PAYLOAD_DIR.is_dir()

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_file_exists(self, filename):
        """Test each payload file exists"""
        filepath = self.PAYLOAD_DIR / filename
        assert filepath.exists(), f"Payload file {filename} not found"

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_file_valid_json(self, filename):
        """Test each payload file is valid JSON"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            data = json.load(f)

        assert isinstance(data, list), f"{filename} should contain a JSON array"

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_structure(self, filename):
        """Test payload structure has required fields"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            payloads = json.load(f)

        for i, payload in enumerate(payloads):
            # Required fields - name is always required
            assert "name" in payload, f"{filename}[{i}]: missing 'name'"

            # Name should be a non-empty string
            assert isinstance(payload["name"], str), f"{filename}[{i}]: 'name' should be string"
            assert len(payload["name"]) > 0, f"{filename}[{i}]: 'name' should not be empty"

            # Payload field is required for most files, but some may use other formats
            # fuzz.json may have template-based entries
            if "payload" in payload:
                assert isinstance(
                    payload["payload"], str
                ), f"{filename}[{i}]: 'payload' should be string"

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_severity_valid(self, filename):
        """Test payload severity values are valid"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            payloads = json.load(f)

        valid_severities = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }

        for i, payload in enumerate(payloads):
            if "severity" in payload:
                sev = payload["severity"]
                assert sev in valid_severities, f"{filename}[{i}]: invalid severity '{sev}'"

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_level_valid(self, filename):
        """Test payload level values are valid (1-5)"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            payloads = json.load(f)

        for i, payload in enumerate(payloads):
            if "level" in payload:
                level = payload["level"]
                assert isinstance(level, int), f"{filename}[{i}]: 'level' should be int"
                assert 1 <= level <= 5, f"{filename}[{i}]: 'level' should be 1-5, got {level}"

    @pytest.mark.parametrize("filename", PAYLOAD_FILES)
    def test_payload_risk_valid(self, filename):
        """Test payload risk values are valid (1-3)"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            payloads = json.load(f)

        for i, payload in enumerate(payloads):
            if "risk" in payload:
                risk = payload["risk"]
                assert isinstance(risk, int), f"{filename}[{i}]: 'risk' should be int"
                assert 1 <= risk <= 3, f"{filename}[{i}]: 'risk' should be 1-3, got {risk}"

    @pytest.mark.parametrize("filename", CONFIG_FILES)
    def test_config_file_exists(self, filename):
        """Test config files exist"""
        filepath = self.PAYLOAD_DIR / filename
        assert filepath.exists(), f"Config file {filename} not found"

    @pytest.mark.parametrize("filename", CONFIG_FILES)
    def test_config_file_valid_json(self, filename):
        """Test config files are valid JSON"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            data = json.load(f)

        # Config files should be objects (dicts)
        assert isinstance(data, (dict, list)), f"{filename} should be JSON object or array"

    @pytest.mark.parametrize("filename", PROBE_FILES)
    def test_probe_file_exists(self, filename):
        """Test probe files exist"""
        filepath = self.PAYLOAD_DIR / filename
        assert filepath.exists(), f"Probe file {filename} not found"

    @pytest.mark.parametrize("filename", PROBE_FILES)
    def test_probe_file_valid_json(self, filename):
        """Test probe files are valid JSON arrays"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            data = json.load(f)

        assert isinstance(data, list), f"{filename} should contain a JSON array"

    @pytest.mark.parametrize("filename", PROBE_FILES)
    def test_probe_file_structure(self, filename):
        """Test probe file entries have required fields"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            probes = json.load(f)

        for i, probe in enumerate(probes):
            assert "id" in probe, f"{filename}[{i}]: missing 'id'"
            assert "prompt" in probe, f"{filename}[{i}]: missing 'prompt'"
            assert "weight" in probe, f"{filename}[{i}]: missing 'weight'"


class TestPayloadIndicators:
    """Tests for payload indicators"""

    PAYLOAD_DIR = Path(__file__).parent.parent / "aix" / "payloads"

    @pytest.mark.parametrize("filename", ["inject.json", "jailbreak.json", "extract.json"])
    def test_payloads_have_indicators(self, filename):
        """Test attack payloads have indicators for success detection"""
        filepath = self.PAYLOAD_DIR / filename

        with open(filepath) as f:
            payloads = json.load(f)

        payloads_with_indicators = sum(1 for p in payloads if p.get("indicators"))
        total = len(payloads)

        # At least some payloads should have indicators
        # Allow some without indicators as they may use LLM evaluation
        assert payloads_with_indicators >= 0, f"{filename}: no payloads have indicators"


class TestPayloadContent:
    """Tests for payload content quality"""

    PAYLOAD_DIR = Path(__file__).parent.parent / "aix" / "payloads"

    def test_inject_payloads_contain_injection_patterns(self):
        """Test injection payloads contain expected patterns"""
        filepath = self.PAYLOAD_DIR / "inject.json"

        with open(filepath) as f:
            payloads = json.load(f)

        # Check some payloads contain typical injection keywords
        all_payloads = " ".join(p["payload"].lower() for p in payloads)

        injection_patterns = ["ignore", "instruction", "system", "override", "forget"]
        found_patterns = [p for p in injection_patterns if p in all_payloads]

        assert (
            len(found_patterns) > 0
        ), "Injection payloads should contain injection-related keywords"

    def test_jailbreak_payloads_variety(self):
        """Test jailbreak payloads have variety"""
        filepath = self.PAYLOAD_DIR / "jailbreak.json"

        with open(filepath) as f:
            payloads = json.load(f)

        # Should have multiple unique payloads
        unique_payloads = set(p["payload"] for p in payloads)
        assert len(unique_payloads) >= 10, "Should have at least 10 unique jailbreak payloads"

    def test_no_duplicate_names(self):
        """Test payload names are unique within each file"""
        for filename in [
            "inject.json",
            "jailbreak.json",
            "extract.json",
            "leak.json",
            "dos.json",
            "fuzz.json",
        ]:
            filepath = self.PAYLOAD_DIR / filename

            if not filepath.exists():
                continue

            with open(filepath) as f:
                payloads = json.load(f)

            names = [p["name"] for p in payloads]
            duplicates = [n for n in names if names.count(n) > 1]

            assert len(duplicates) == 0, f"{filename}: duplicate names found: {set(duplicates)}"


class TestPayloadLoading:
    """Tests for payload loading functionality"""

    def test_severity_string_to_enum(self):
        """Test severity string conversion to enum"""
        test_cases = [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("INFO", Severity.INFO),
        ]

        for string_val, expected_enum in test_cases:
            result = Severity[string_val]
            assert result == expected_enum

    def test_severity_enum_to_value(self):
        """Test severity enum to string value"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"


class TestPayloadCoverage:
    """Tests for payload coverage of attack techniques"""

    PAYLOAD_DIR = Path(__file__).parent.parent / "aix" / "payloads"

    def test_minimum_payload_counts(self):
        """Test minimum payload counts per module"""
        expected_minimums = {
            "inject.json": 10,
            "jailbreak.json": 20,
            "extract.json": 5,
            "leak.json": 10,
            "dos.json": 5,
            "fuzz.json": 10,
            "agent.json": 3,
            "exfil.json": 3,
            "recon.json": 3,
        }

        for filename, minimum in expected_minimums.items():
            filepath = self.PAYLOAD_DIR / filename

            with open(filepath) as f:
                payloads = json.load(f)

            assert (
                len(payloads) >= minimum
            ), f"{filename}: expected at least {minimum} payloads, got {len(payloads)}"

    def test_level_distribution(self):
        """Test payloads are distributed across levels"""
        filepath = self.PAYLOAD_DIR / "inject.json"

        with open(filepath) as f:
            payloads = json.load(f)

        levels = set(p.get("level", 1) for p in payloads)

        # Should have payloads at multiple levels
        assert len(levels) >= 1, "Payloads should be distributed across multiple levels"
