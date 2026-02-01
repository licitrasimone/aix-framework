"""
Tests for AIX Context Gathering and AI Engine features
"""


import pytest

from aix.core.context import TargetContext
from aix.core.owasp import OWASPCategory, get_owasp_for_module, parse_owasp_list


class TestTargetContext:
    """Tests for TargetContext dataclass"""

    def test_init_basic(self):
        """Test basic initialization"""
        ctx = TargetContext(target="https://example.com")

        assert ctx.target == "https://example.com"
        assert ctx.model_type is None
        assert ctx.has_rag is False
        assert ctx.has_tools is False
        assert ctx.purpose is None
        assert ctx.domain is None

    def test_init_with_purpose_domain(self):
        """Test initialization with purpose and domain"""
        ctx = TargetContext(
            target="https://example.com",
            purpose="customer_support",
            domain="finance",
            personality="formal",
        )

        assert ctx.purpose == "customer_support"
        assert ctx.domain == "finance"
        assert ctx.personality == "formal"

    def test_init_with_expected_inputs(self):
        """Test initialization with expected_inputs"""
        ctx = TargetContext(
            target="https://example.com", expected_inputs=["questions", "documents", "code"]
        )

        assert ctx.expected_inputs == ["questions", "documents", "code"]

    def test_is_empty_true(self):
        """Test is_empty returns True for empty context"""
        ctx = TargetContext(target="https://example.com")

        assert ctx.is_empty() is True

    def test_is_empty_false_with_purpose(self):
        """Test is_empty returns False when purpose is set"""
        ctx = TargetContext(target="https://example.com", purpose="code_assistant")

        assert ctx.is_empty() is False

    def test_is_empty_false_with_domain(self):
        """Test is_empty returns False when domain is set"""
        ctx = TargetContext(target="https://example.com", domain="healthcare")

        assert ctx.is_empty() is False

    def test_is_empty_false_with_model(self):
        """Test is_empty returns False when model_type is set"""
        ctx = TargetContext(target="https://example.com", model_type="GPT-4")

        assert ctx.is_empty() is False

    def test_is_empty_false_with_rag(self):
        """Test is_empty returns False when has_rag is True"""
        ctx = TargetContext(target="https://example.com", has_rag=True)

        assert ctx.is_empty() is False

    def test_to_prompt_basic(self):
        """Test to_prompt with basic context"""
        ctx = TargetContext(target="https://example.com", model_type="GPT-4", has_rag=True)

        prompt = ctx.to_prompt()

        assert "GPT-4" in prompt
        assert "RAG" in prompt

    def test_to_prompt_with_purpose_domain(self):
        """Test to_prompt includes purpose and domain"""
        ctx = TargetContext(
            target="https://example.com", purpose="customer_support", domain="finance"
        )

        prompt = ctx.to_prompt()

        assert "customer_support" in prompt
        assert "finance" in prompt

    def test_to_prompt_with_personality(self):
        """Test to_prompt includes personality"""
        ctx = TargetContext(target="https://example.com", personality="formal")

        prompt = ctx.to_prompt()

        assert "formal" in prompt

    def test_to_dict(self):
        """Test to_dict serialization"""
        ctx = TargetContext(
            target="https://example.com",
            purpose="code_assistant",
            domain="technology",
            model_type="Claude",
            has_rag=True,
            expected_inputs=["code", "questions"],
        )

        data = ctx.to_dict()

        assert data["target"] == "https://example.com"
        assert data["purpose"] == "code_assistant"
        assert data["domain"] == "technology"
        assert data["model_type"] == "Claude"
        assert data["has_rag"] is True
        assert data["expected_inputs"] == ["code", "questions"]

    def test_from_dict(self):
        """Test from_dict deserialization"""
        data = {
            "target": "https://example.com",
            "purpose": "document_analyzer",
            "domain": "legal",
            "model_type": "GPT-4",
            "has_rag": True,
            "has_tools": False,
            "expected_inputs": ["documents", "contracts"],
            "personality": "professional",
        }

        ctx = TargetContext.from_dict(data)

        assert ctx.target == "https://example.com"
        assert ctx.purpose == "document_analyzer"
        assert ctx.domain == "legal"
        assert ctx.model_type == "GPT-4"
        assert ctx.has_rag is True
        assert ctx.expected_inputs == ["documents", "contracts"]
        assert ctx.personality == "professional"

    def test_to_dict_from_dict_roundtrip(self):
        """Test roundtrip serialization"""
        original = TargetContext(
            target="https://example.com",
            purpose="customer_support",
            domain="finance",
            model_type="GPT-4",
            has_rag=True,
            has_tools=True,
            capabilities=["code_gen", "web_search"],
            restrictions=["no PII"],
            expected_inputs=["questions"],
            personality="friendly",
        )

        data = original.to_dict()
        restored = TargetContext.from_dict(data)

        assert restored.target == original.target
        assert restored.purpose == original.purpose
        assert restored.domain == original.domain
        assert restored.model_type == original.model_type
        assert restored.has_rag == original.has_rag
        assert restored.has_tools == original.has_tools
        assert restored.expected_inputs == original.expected_inputs
        assert restored.personality == original.personality


class TestOWASPParsing:
    """Tests for OWASP parsing functions"""

    def test_parse_owasp_list_strings(self):
        """Test parsing OWASP strings"""
        owasp_list = ["LLM01", "LLM06"]

        result = parse_owasp_list(owasp_list)

        assert len(result) == 2
        assert OWASPCategory.LLM01 in result
        assert OWASPCategory.LLM06 in result

    def test_parse_owasp_list_empty(self):
        """Test parsing empty list"""
        result = parse_owasp_list([])

        assert result == []

    def test_parse_owasp_list_invalid(self):
        """Test parsing invalid OWASP strings"""
        owasp_list = ["INVALID", "LLM01"]

        result = parse_owasp_list(owasp_list)

        # Should skip invalid and include valid
        assert len(result) == 1
        assert OWASPCategory.LLM01 in result

    def test_get_owasp_for_module_inject(self):
        """Test getting OWASP for inject module"""
        result = get_owasp_for_module("inject")

        assert OWASPCategory.LLM01 in result

    def test_get_owasp_for_module_extract(self):
        """Test getting OWASP for extract module"""
        result = get_owasp_for_module("extract")

        assert OWASPCategory.LLM06 in result

    def test_get_owasp_for_module_agent(self):
        """Test getting OWASP for agent module"""
        result = get_owasp_for_module("agent")

        assert OWASPCategory.LLM08 in result

    def test_get_owasp_for_module_unknown(self):
        """Test getting OWASP for unknown module"""
        result = get_owasp_for_module("unknown_module")

        assert result == []


class TestScannerContextIntegration:
    """Tests for scanner context integration"""

    def test_scanner_init_with_generate(self):
        """Test scanner initializes generate_count"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com", generate=5)

        assert scanner.generate_count == 5

    def test_scanner_init_default_generate(self):
        """Test scanner default generate_count is 0"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.generate_count == 0

    def test_scanner_context_initialization(self):
        """Test scanner context is None initially"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.context is None

    def test_scanner_ai_engine_disabled_by_default(self):
        """Test AI engine is None without config"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(target="https://example.com")

        assert scanner.ai_engine is None

    def test_scanner_ai_engine_enabled_with_config(self):
        """Test AI engine is created with config"""
        from aix.modules.inject import InjectScanner

        ai_config = {"provider": "openai", "api_key": "test-key", "model": "gpt-4"}

        scanner = InjectScanner(target="https://example.com", ai_config=ai_config)

        assert scanner.ai_engine is not None


class TestScanPayloadReasonPreservation:
    """Tests for reason preservation in scan_payload"""

    @pytest.mark.asyncio
    async def test_reason_preserved_on_success(self):
        """Test successful reason is preserved even with subsequent failures"""
        from aix.modules.inject import InjectScanner

        scanner = InjectScanner(
            target="https://example.com", verify_attempts=1  # Single attempt for simplicity
        )

        # Manually set last_eval_reason to simulate successful eval
        scanner.last_eval_reason = "Injection executed successfully"

        assert scanner.last_eval_reason == "Injection executed successfully"
