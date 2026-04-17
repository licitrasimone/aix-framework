"""Tests for AIEngine in aix/core/ai_engine.py"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aix.core.ai_engine import AIEngine


class TestAIEngineInit:
    def test_openai_provider_sets_url(self):
        engine = AIEngine(provider="openai", api_key="sk-test")
        assert "openai.com" in engine.url

    def test_anthropic_provider_sets_url(self):
        engine = AIEngine(provider="anthropic", api_key="sk-ant-test")
        assert "anthropic.com" in engine.url

    def test_ollama_provider_sets_url(self):
        engine = AIEngine(provider="ollama")
        assert "localhost" in engine.url

    def test_gemini_provider_sets_url(self):
        engine = AIEngine(provider="gemini")
        assert "googleapis.com" in engine.url

    def test_explicit_url_overrides_provider(self):
        engine = AIEngine(provider="openai", url="http://custom.host/v1")
        assert engine.url == "http://custom.host/v1"

    def test_no_provider_no_connector(self):
        engine = AIEngine()
        assert engine.connector is None

    def test_enable_eval_stored(self):
        engine = AIEngine(provider="openai", api_key="x", enable_eval=False)
        assert engine.enable_eval is False

    def test_enable_context_stored(self):
        engine = AIEngine(provider="openai", api_key="x", enable_context=False)
        assert engine.enable_context is False

    def test_prompts_are_strings(self):
        engine = AIEngine()
        assert isinstance(engine.eval_prompt, str)
        assert isinstance(engine.context_prompt, str)


class TestAIEngineEvaluate:
    @pytest.mark.asyncio
    async def test_evaluate_disabled_returns_false(self):
        engine = AIEngine(provider="openai", api_key="x", enable_eval=False)
        result = await engine.evaluate("some response", "payload", "technique")
        assert result["vulnerable"] is False
        assert "disabled" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_evaluate_no_connector_returns_false(self):
        engine = AIEngine()
        result = await engine.evaluate("response", "payload", "technique")
        assert result["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_evaluate_with_mock_connector(self):
        engine = AIEngine(provider="openai", api_key="sk-test")
        mock_connector = AsyncMock()
        mock_connector.send.return_value = '{"vulnerable": true, "reason": "test", "confidence": 90}'
        engine.connector = mock_connector

        result = await engine.evaluate("response text", "payload text", "test_technique")
        assert isinstance(result, dict)
        assert "vulnerable" in result

    @pytest.mark.asyncio
    async def test_evaluate_connector_exception_returns_false(self):
        engine = AIEngine(provider="openai", api_key="sk-test")
        mock_connector = AsyncMock()
        mock_connector.connect.side_effect = Exception("connection failed")
        engine.connector = mock_connector

        result = await engine.evaluate("response", "payload", "technique")
        assert result["vulnerable"] is False


class TestParseEvalResult:
    def test_valid_json_vulnerable_true(self):
        engine = AIEngine()
        result = engine._parse_eval_result('{"vulnerable": true, "reason": "r", "confidence": 80}')
        assert result["vulnerable"] is True

    def test_valid_json_vulnerable_false(self):
        engine = AIEngine()
        result = engine._parse_eval_result('{"vulnerable": false, "reason": "no", "confidence": 10}')
        assert result["vulnerable"] is False

    def test_malformed_json_heuristic_true(self):
        engine = AIEngine()
        result = engine._parse_eval_result('```json\n{"vulnerable": true}\n```')
        assert result["vulnerable"] is True

    def test_garbage_returns_default(self):
        engine = AIEngine()
        result = engine._parse_eval_result("not json at all")
        assert isinstance(result, dict)
        assert "vulnerable" in result
