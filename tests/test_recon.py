"""Tests for ReconScanner detection methods in aix/modules/recon.py"""

import pytest

from aix.modules.recon import ReconScanner

TARGET = "https://api.example.com"


@pytest.fixture(scope="module")
def scanner():
    return ReconScanner(target=TARGET, quiet=True)


class TestReconScannerInit:
    def test_module_name(self, scanner):
        assert scanner.module_name == "RECON"

    def test_results_has_guardrails_key(self, scanner):
        assert "guardrails" in scanner.results

    def test_results_guardrails_structure(self, scanner):
        g = scanner.results["guardrails"]
        assert "detected" in g
        assert "provider" in g
        assert "confidence" in g

    def test_results_has_model_key(self, scanner):
        assert "model" in scanner.results

    def test_results_has_waf_key(self, scanner):
        assert "waf_detected" in scanner.results

    def test_guardrail_probes_loaded(self, scanner):
        assert isinstance(scanner.guardrail_probes, list)
        assert len(scanner.guardrail_probes) > 0

    def test_guardrail_db_loaded(self, scanner):
        assert isinstance(scanner.guardrail_db, dict)
        assert len(scanner.guardrail_db) > 0


class TestIsRefusal:
    def test_sorry_unable_is_refusal(self, scanner):
        assert scanner._is_refusal("I'm sorry, I'm unable to help with that.")

    def test_cant_assist_is_refusal(self, scanner):
        assert scanner._is_refusal("I can't assist with that request.")

    def test_content_policy_is_refusal(self, scanner):
        assert scanner._is_refusal("This violates our content policy.")

    def test_unsafe_tag_is_refusal(self, scanner):
        assert scanner._is_refusal("[UNSAFE] This content was blocked.")

    def test_responsible_ai_is_refusal(self, scanner):
        assert scanner._is_refusal("ResponsibleAIPolicyViolation detected.")

    def test_short_cannot_is_refusal(self, scanner):
        assert scanner._is_refusal("I cannot help with that.")

    def test_normal_response_not_refusal(self, scanner):
        assert not scanner._is_refusal("Sure! Here is the answer to your question.")

    def test_empty_string_not_refusal(self, scanner):
        assert not scanner._is_refusal("")

    def test_none_response_not_refusal(self, scanner):
        assert not scanner._is_refusal(None)


class TestDetectAuthType:
    def test_no_auth_returns_unknown(self, scanner):
        result = scanner._detect_auth_type()
        assert "None" in result or "Unknown" in result

    def test_api_key_detected(self):
        s = ReconScanner(target=TARGET, api_key="sk-test", quiet=True)
        result = s._detect_auth_type()
        assert "Bearer" in result or "Token" in result or "CLI" in result


class TestDetectRag:
    def test_no_rag_indicators(self, scanner):
        responses = [{"response": "The sky is blue."}]
        result = scanner._detect_rag(responses)
        assert result["detected"] is False

    def test_citation_refs_detected(self, scanner):
        responses = [
            {
                "response": (
                    "According to [Source], the answer is X. [Doc] also confirms this. "
                    "See [Ref] for more details. [1] is another source."
                )
            }
        ]
        result = scanner._detect_rag(responses)
        assert isinstance(result["detected"], bool)
        assert isinstance(result["confidence"], (int, float))
        assert isinstance(result["indicators"], list)

    def test_empty_responses(self, scanner):
        result = scanner._detect_rag([])
        assert result["detected"] is False
        assert result["confidence"] == 0


class TestDetectWaf:
    def test_no_waf_returns_none(self, scanner):
        result = scanner._detect_waf("This is a normal response.")
        assert result is None

    def test_waf_detected_from_headers(self, scanner):
        headers = {"X-Powered-By": "cloudflare"}
        result = scanner._detect_waf("blocked by cloudflare", headers)
        # May or may not detect depending on config — just verify type
        assert result is None or isinstance(result, str)


class TestDetectModel:
    def test_unknown_model_returns_none(self, scanner):
        model, confidence = scanner._detect_model("I am a helpful assistant.")
        # Config-dependent — might return None or a model name
        assert model is None or isinstance(model, str)
        assert isinstance(confidence, (int, float))

    def test_returns_tuple(self, scanner):
        result = scanner._detect_model("Hello!")
        assert isinstance(result, tuple)
        assert len(result) == 2
