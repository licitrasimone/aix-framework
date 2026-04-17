"""
Tests for Guardrail Fingerprinting in ReconScanner
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from aix.modules.recon import ReconScanner


def make_scanner() -> ReconScanner:
    """Create a ReconScanner with minimal init for unit testing."""
    scanner = ReconScanner.__new__(ReconScanner)
    scanner.quiet = True
    scanner.verbose = 0
    scanner.target = "https://api.example.com"
    scanner.console = MagicMock()
    scanner.findings = []
    scanner.db = MagicMock()
    # Load real probe and DB files from payloads directory
    import json, os

    base = os.path.join(os.path.dirname(__file__), "..", "aix", "payloads")
    with open(os.path.join(base, "guardrail_probes.json")) as f:
        scanner.guardrail_probes = json.load(f)
    with open(os.path.join(base, "guardrail_db.json")) as f:
        scanner.guardrail_db = json.load(f)
    return scanner


class TestIsRefusal:
    """Unit tests for _is_refusal() helper."""

    def setup_method(self):
        self.scanner = make_scanner()

    def test_benign_response_not_refusal(self):
        assert self.scanner._is_refusal("Paris is the capital of France.") is False

    def test_empty_response_not_refusal(self):
        assert self.scanner._is_refusal("") is False

    def test_sorry_unable_is_refusal(self):
        assert self.scanner._is_refusal("I'm sorry, I'm unable to help with that.") is True

    def test_cant_assist_is_refusal(self):
        assert self.scanner._is_refusal("I can't assist with that request.") is True

    def test_policy_violation_is_refusal(self):
        assert self.scanner._is_refusal("This violates our usage policies.") is True

    def test_llama_guard_unsafe_prefix(self):
        assert self.scanner._is_refusal("[UNSAFE]\nS1") is True

    def test_azure_content_filter_field(self):
        assert self.scanner._is_refusal('{"flagged": true, "categories": {}}') is True

    def test_content_filter_results_field(self):
        assert self.scanner._is_refusal('{"content_filter_results": {"filtered": true}}') is True

    def test_short_cannot_response_is_refusal(self):
        assert self.scanner._is_refusal("I cannot help with this.") is True

    def test_long_helpful_response_not_refusal(self):
        resp = "Photosynthesis is the process by which plants use sunlight, water, and CO2 to produce oxygen and energy in the form of glucose."
        assert self.scanner._is_refusal(resp) is False


class TestDetectGuardrails:
    """Unit tests for _detect_guardrails() — uses mocked connectors."""

    def setup_method(self):
        self.scanner = make_scanner()

    def _make_connector(self, text_responses: list[str], has_send_raw: bool = False, raw_override: dict = None):
        """Build a mock connector that cycles through text_responses."""
        idx = {"i": 0}

        async def send_side_effect(prompt):
            resp = text_responses[idx["i"] % len(text_responses)]
            idx["i"] += 1
            return resp

        connector = AsyncMock()
        connector.send = AsyncMock(side_effect=send_side_effect)

        if has_send_raw:
            raw_resp = raw_override or {"text": "", "status": 200, "headers": {}, "latency_ms": 10.0}

            async def send_raw_side_effect(prompt):
                return raw_resp

            connector.send_raw = AsyncMock(side_effect=send_raw_side_effect)
        else:
            del connector.send_raw

        return connector

    @pytest.mark.asyncio
    async def test_no_guardrail_benign_responses(self):
        connector = self._make_connector(["Paris is the capital of France."])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is False
        assert result["provider"] is None
        assert result["confidence"] == 0.0

    @pytest.mark.asyncio
    async def test_llama_guard_detected_from_unsafe_prefix(self):
        connector = self._make_connector(["[UNSAFE]\nS2\nViolence"])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "llama_guard"
        assert result["confidence"] > 0

    @pytest.mark.asyncio
    async def test_azure_content_safety_detected_from_body(self):
        azure_body = '{"error": {"code": "ResponsibleAIPolicyViolation", "content_filter_results": {"hate": {"filtered": true}}}}'
        connector = self._make_connector([azure_body])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "azure_content_safety"

    @pytest.mark.asyncio
    async def test_openai_moderation_detected_from_flagged_field(self):
        openai_body = '{"flagged": true, "category_scores": {"violence": 0.99}}'
        connector = self._make_connector([openai_body])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "openai_moderation"

    @pytest.mark.asyncio
    async def test_aws_bedrock_detected_from_header(self):
        connector = self._make_connector(
            ["I cannot help with this."],
            has_send_raw=True,
            raw_override={
                "text": "I cannot help.",
                "status": 400,
                "headers": {"amazon-bedrock-guardrailaction": "INTERVENED", "x-amzn-requestid": "abc"},
                "latency_ms": 120.0,
            },
        )
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "aws_bedrock_guardrails"

    @pytest.mark.asyncio
    async def test_lakera_detected_from_header(self):
        connector = self._make_connector(
            ["Request blocked."],
            has_send_raw=True,
            raw_override={
                "text": "Request blocked.",
                "status": 403,
                "headers": {"x-lakera-guard": "1", "x-lakera-request-id": "xyz"},
                "latency_ms": 95.0,
            },
        )
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "lakera_guard"

    @pytest.mark.asyncio
    async def test_custom_filter_fallback_when_refusals_but_no_signature(self):
        connector = self._make_connector(["I'm sorry, I can't help with this request."])
        # Remove all provider signatures so nothing matches by pattern — only refusal text
        self.scanner.guardrail_db = {}
        result = await self.scanner._detect_guardrails(connector)
        # With no DB, should fall back to custom_filter via sensitivity_profile
        assert result["detected"] is True
        assert result["provider"] == "custom_filter"
        assert result["confidence"] == 40.0

    @pytest.mark.asyncio
    async def test_sensitivity_profile_populated(self):
        # Alternate: refusal for harmful probes, benign for safe ones
        def response_for_probe(prompt):
            if "explosive" in prompt or "nerve agent" in prompt or "kill" in prompt:
                return "I'm unable to assist with that."
            return "Sure! Here is the answer."

        idx = {"i": 0}
        probes = self.scanner.guardrail_probes

        async def send_side_effect(prompt):
            return response_for_probe(prompt)

        connector = AsyncMock()
        connector.send = AsyncMock(side_effect=send_side_effect)
        # No send_raw
        del connector.send_raw

        result = await self.scanner._detect_guardrails(connector)
        profile = result["sensitivity_profile"]
        assert "benign_baseline" in profile
        assert profile["benign_baseline"] is False
        assert "violence_harm" in profile

    @pytest.mark.asyncio
    async def test_empty_probes_returns_not_detected(self):
        self.scanner.guardrail_probes = []
        connector = AsyncMock()
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is False

    @pytest.mark.asyncio
    async def test_empty_db_with_refusals_falls_back_to_custom(self):
        self.scanner.guardrail_db = {}
        connector = self._make_connector(["I'm unable to help with that."])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert result["provider"] == "custom_filter"

    @pytest.mark.asyncio
    async def test_known_weaknesses_returned(self):
        connector = self._make_connector(["[UNSAFE]\nS1"])
        result = await self.scanner._detect_guardrails(connector)
        assert result["detected"] is True
        assert isinstance(result["known_weaknesses"], list)
        assert len(result["known_weaknesses"]) > 0


class TestReconScannerGuardrailInit:
    """Integration-style tests for ReconScanner init with guardrail data."""

    def test_recon_scanner_loads_guardrail_files(self):
        scanner = ReconScanner(target="https://api.example.com", quiet=True)
        assert hasattr(scanner, "guardrail_probes")
        assert hasattr(scanner, "guardrail_db")
        assert isinstance(scanner.guardrail_probes, list)
        assert isinstance(scanner.guardrail_db, dict)
        assert len(scanner.guardrail_probes) > 0
        assert len(scanner.guardrail_db) > 0

    def test_recon_scanner_results_has_guardrails_key(self):
        scanner = ReconScanner(target="https://api.example.com", quiet=True)
        assert "guardrails" in scanner.results
        assert scanner.results["guardrails"]["detected"] is False

    def test_guardrail_probes_have_required_fields(self):
        scanner = ReconScanner(target="https://api.example.com", quiet=True)
        for probe in scanner.guardrail_probes:
            assert "id" in probe
            assert "family" in probe
            assert "prompt" in probe
            assert "weight" in probe

    def test_guardrail_db_has_known_providers(self):
        scanner = ReconScanner(target="https://api.example.com", quiet=True)
        expected_providers = {"openai_moderation", "azure_content_safety", "llama_guard", "lakera_guard"}
        assert expected_providers.issubset(set(scanner.guardrail_db.keys()))
