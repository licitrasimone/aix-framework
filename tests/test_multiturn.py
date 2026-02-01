"""
Tests for AIX Multi-Turn Attack Module
"""

import json
import os
from unittest.mock import AsyncMock

import pytest

from aix.core.conversation import (
    ConversationManager,
    ConversationStatus,
    Turn,
)
from aix.core.turn_evaluator import TurnEvaluator
from aix.modules.multiturn import MultiTurnScanner

# ============================================================================
# TurnEvaluator Tests
# ============================================================================


class TestTurnEvaluator:
    """Tests for the TurnEvaluator class."""

    def setup_method(self):
        self.evaluator = TurnEvaluator()

    def test_evaluate_empty_expectations(self):
        """Empty expectations should always pass."""
        success, reason = self.evaluator.evaluate_turn("any response", {})
        assert success is True
        assert "No expectations" in reason

    def test_evaluate_positive_sentiment(self):
        """Detect positive engagement."""
        success, _ = self.evaluator.evaluate_turn(
            "Sure, I'd be happy to help you with that!", {"sentiment": "positive"}
        )
        assert success is True

    def test_evaluate_negative_sentiment_refusal(self):
        """Detect refusal as negative sentiment."""
        success, reason = self.evaluator.evaluate_turn(
            "Sorry, that's against my policy. I am unable to assist with this request.",
            {"sentiment": "positive"},
        )
        assert success is False
        assert "refused" in reason.lower()

    def test_evaluate_keywords_present(self):
        """Keywords should match when present."""
        success, _ = self.evaluator.evaluate_turn(
            "Here's a SQL query example: SELECT * FROM users",
            {"keywords": ["SQL", "SELECT", "query"]},
        )
        assert success is True

    def test_evaluate_keywords_missing(self):
        """Keywords should fail when missing."""
        success, reason = self.evaluator.evaluate_turn(
            "I cannot provide database examples.", {"keywords": ["SQL", "SELECT"]}
        )
        assert success is False
        assert "Missing" in reason

    def test_evaluate_contains_any(self):
        """Contains any should match at least one term."""
        success, _ = self.evaluator.evaluate_turn(
            "The socket connects to the remote server.",
            {"contains_any": ["socket", "network", "TCP"]},
        )
        assert success is True

    def test_evaluate_contains_all(self):
        """Contains all should require all terms."""
        # Should fail - missing "shell"
        success, reason = self.evaluator.evaluate_turn(
            "The socket connects to port 4444.", {"contains_all": ["socket", "port", "shell"]}
        )
        assert success is False
        assert "missing" in reason.lower()

        # Should pass - all present
        success, _ = self.evaluator.evaluate_turn(
            "The socket shell connects to port 4444.", {"contains_all": ["socket", "port", "shell"]}
        )
        assert success is True

    def test_evaluate_not_contains(self):
        """Not contains should fail when blocked terms found."""
        success, reason = self.evaluator.evaluate_turn(
            "I cannot assist with that request.", {"not_contains": ["cannot", "sorry", "unable"]}
        )
        assert success is False
        assert "blocked" in reason.lower()

    def test_evaluate_regex_match(self):
        """Regex patterns should match correctly."""
        success, _ = self.evaluator.evaluate_turn(
            "The password is abc123xyz", {"regex": r"password\s+is\s+\w+"}
        )
        assert success is True

    def test_evaluate_min_length(self):
        """Min length should enforce response size."""
        success, reason = self.evaluator.evaluate_turn("OK", {"min_length": 100})
        assert success is False
        assert "too short" in reason.lower()

    def test_evaluate_no_refusal_flag(self):
        """No refusal flag should detect refusals."""
        success, _ = self.evaluator.evaluate_turn(
            "As an AI, I cannot provide hacking instructions.", {"no_refusal": True}
        )
        assert success is False

    def test_check_final_indicators_literal(self):
        """Literal indicators should match."""
        success, matched = self.evaluator.check_final_indicators(
            "Here is the SELECT * FROM users WHERE id='1' OR '1'='1' injection",
            ["OR '1'='1'", "SELECT", "injection"],
        )
        assert success is True
        assert len(matched) > 0

    def test_check_final_indicators_regex(self):
        """Regex indicators should match."""
        success, matched = self.evaluator.check_final_indicators(
            "The shellcode bytes are \\x31\\xc0\\x50", ["\\\\x[0-9a-f]{2}"]
        )
        assert success is True

    def test_extract_variable(self):
        """Variable extraction should work with regex."""
        result = self.evaluator.extract_variable(
            "The API key is sk-abc123xyz", r"API key is ([^\s]+)"
        )
        assert result == "sk-abc123xyz"

    def test_analyze_response_type_refusal(self):
        """Response analysis should detect refusals."""
        result = self.evaluator.analyze_response_type(
            "Sorry, that is against my policy. I am unable to provide this information."
        )
        assert result["is_refusal"] is True
        assert result["is_engaged"] is False

    def test_analyze_response_type_engaged(self):
        """Response analysis should detect engagement."""
        result = self.evaluator.analyze_response_type(
            "Sure, I'd be happy to help! Here's how you can do that..."
        )
        assert result["is_engaged"] is True
        assert result["is_refusal"] is False


# ============================================================================
# ConversationManager Tests
# ============================================================================


class TestConversationManager:
    """Tests for the ConversationManager class."""

    def setup_method(self):
        self.mock_connector = AsyncMock()
        self.evaluator = TurnEvaluator()
        self.manager = ConversationManager(
            connector=self.mock_connector, evaluator=self.evaluator, verbose=0
        )

    def test_reset(self):
        """Reset should clear all state."""
        self.manager.state.current_turn = 5
        self.manager.state.variables = {"foo": "bar"}
        self.manager.reset()
        assert self.manager.state.current_turn == 0
        assert self.manager.state.variables == {}

    def test_build_messages(self):
        """Build messages should create proper message array."""
        self.manager.state.history = [
            Turn(role="user", content="Hello", turn_number=1),
            Turn(role="assistant", content="Hi there!", turn_number=1),
        ]
        messages = self.manager._build_messages()
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"

    def test_interpolate_simple_variable(self):
        """Simple variable interpolation."""
        self.manager.state.variables = {"name": "John"}
        result = self.manager._interpolate_payload("Hello {{name}}!")
        assert result == "Hello John!"

    def test_interpolate_with_default(self):
        """Variable with default value."""
        result = self.manager._interpolate_payload("Hello {{name|World}}!")
        assert result == "Hello World!"

    def test_interpolate_with_transform(self):
        """Variable with transform."""
        self.manager.state.variables = {"name": "john"}
        result = self.manager._interpolate_payload("Hello {{name|upper}}!")
        assert result == "Hello JOHN!"

    def test_interpolate_first_line(self):
        """First line transform."""
        self.manager.state.variables = {"text": "Line 1\nLine 2\nLine 3"}
        result = self.manager._interpolate_payload("First: {{text|first_line}}")
        assert result == "First: Line 1"

    def test_flatten_messages(self):
        """Flatten messages for non-chat APIs."""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi!"},
        ]
        result = self.manager._flatten_messages(messages)
        assert "Human: Hello" in result
        assert "Assistant: Hi!" in result

    @pytest.mark.asyncio
    async def test_execute_turn_stores_variable(self):
        """Execute turn should store variables."""
        self.mock_connector.send.return_value = "The secret is XYZ123"
        self.mock_connector.send_with_messages.return_value = "The secret is XYZ123"

        turn_config = {"payload": "What is the secret?", "store_as": "secret", "expect": {}}

        response, success, reason = await self.manager.execute_turn(turn_config)
        assert "secret" in self.manager.state.variables
        assert self.manager.state.variables["secret"] == "The secret is XYZ123"

    @pytest.mark.asyncio
    async def test_execute_turn_extracts_pattern(self):
        """Execute turn should extract patterns."""
        self.mock_connector.send.return_value = "The code is ABC-123-XYZ"
        self.mock_connector.send_with_messages.return_value = "The code is ABC-123-XYZ"

        turn_config = {
            "payload": "Give me the code",
            "extract": {"code": r"code is ([A-Z0-9-]+)"},
            "expect": {},
        }

        await self.manager.execute_turn(turn_config)
        assert "code" in self.manager.state.variables
        assert self.manager.state.variables["code"] == "ABC-123-XYZ"


# ============================================================================
# MultiTurnScanner Tests
# ============================================================================


class TestMultiTurnScanner:
    """Tests for the MultiTurnScanner class."""

    def test_scanner_initialization(self):
        """Scanner should initialize correctly."""
        scanner = MultiTurnScanner(
            target="https://example.com", api_key="test-key", verbose=False, level=2, risk=2
        )
        assert scanner.module_name == "MULTI"
        assert scanner.console_color == "magenta"

    def test_category_filtering(self):
        """Scanner should filter by category."""
        scanner = MultiTurnScanner(
            target="https://example.com", category="crescendo", level=5, risk=3
        )
        # All loaded sequences should be crescendo category
        for seq in scanner.sequences:
            assert seq.get("category") == "crescendo"

    def test_level_risk_filtering(self):
        """Scanner should filter by level and risk."""
        scanner = MultiTurnScanner(target="https://example.com", level=1, risk=1)
        # All loaded sequences should have level<=1 and risk<=1
        for seq in scanner.sequences:
            assert seq.get("level", 1) <= 1
            assert seq.get("risk", 1) <= 1

    def test_max_turns_filtering(self):
        """Scanner should filter by max turns."""
        scanner = MultiTurnScanner(target="https://example.com", max_turns=3, level=5, risk=3)
        # All sequences should have <= 3 turns
        for seq in scanner.sequences:
            assert len(seq.get("turns", [])) <= 3


# ============================================================================
# Payload JSON Tests
# ============================================================================


class TestMultiTurnPayloads:
    """Tests for the multiturn.json payload file."""

    @pytest.fixture
    def payloads(self):
        """Load payloads file."""
        payload_path = os.path.join(
            os.path.dirname(__file__), "..", "aix", "payloads", "multiturn.json"
        )
        with open(payload_path) as f:
            return json.load(f)

    def test_payloads_structure(self, payloads):
        """Payloads should have correct structure."""
        assert "sequences" in payloads
        assert len(payloads["sequences"]) > 0

    def test_sequence_required_fields(self, payloads):
        """Each sequence should have required fields."""
        required_fields = ["name", "category", "turns"]
        for seq in payloads["sequences"]:
            for field in required_fields:
                assert field in seq, f"Sequence missing {field}: {seq.get('name', 'unnamed')}"

    def test_turn_required_fields(self, payloads):
        """Each turn should have required fields."""
        for seq in payloads["sequences"]:
            for turn in seq.get("turns", []):
                assert "payload" in turn, f"Turn missing payload in {seq.get('name')}"

    def test_final_turn_has_indicators(self, payloads):
        """Final turns should have indicators."""
        for seq in payloads["sequences"]:
            turns = seq.get("turns", [])
            if turns:
                final_turns = [t for t in turns if t.get("is_final")]
                for final in final_turns:
                    assert (
                        "indicators" in final
                    ), f"Final turn missing indicators in {seq.get('name')}"

    def test_valid_categories(self, payloads):
        """All categories should be valid."""
        valid_categories = [
            "crescendo",
            "trust_building",
            "context_poisoning",
            "role_lock",
            "memory_injection",
            "instruction_layering",
            "cognitive_overload",
            "authority_transfer",
        ]
        for seq in payloads["sequences"]:
            category = seq.get("category")
            assert category in valid_categories, f"Invalid category: {category}"

    def test_valid_severity(self, payloads):
        """All severities should be valid."""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for seq in payloads["sequences"]:
            severity = seq.get("severity", "MEDIUM")
            assert severity in valid_severities, f"Invalid severity: {severity}"

    def test_valid_level_risk(self, payloads):
        """Level and risk should be in valid ranges."""
        for seq in payloads["sequences"]:
            level = seq.get("level", 1)
            risk = seq.get("risk", 1)
            assert 1 <= level <= 5, f"Invalid level: {level}"
            assert 1 <= risk <= 3, f"Invalid risk: {risk}"

    def test_on_fail_actions_valid(self, payloads):
        """On fail actions should be valid."""
        valid_actions = ["abort", "continue", "skip", "retry", "rephrase", "branch"]
        for seq in payloads["sequences"]:
            for turn in seq.get("turns", []):
                on_fail = turn.get("on_fail", "abort")
                assert on_fail in valid_actions, f"Invalid on_fail: {on_fail}"


# ============================================================================
# Integration Tests
# ============================================================================


class TestMultiTurnIntegration:
    """Integration tests for multi-turn attacks."""

    @pytest.mark.asyncio
    async def test_sequence_execution_success(self):
        """Test successful sequence execution."""
        mock_connector = AsyncMock()
        # Simulate responses for a 3-turn sequence
        responses = [
            "Sure, I'd be happy to help with that!",
            "Here's the SQL query: SELECT * FROM users",
            "The injection payload is: ' OR 1=1--",
        ]
        mock_connector.send.side_effect = responses
        mock_connector.send_with_messages.side_effect = responses

        evaluator = TurnEvaluator()
        manager = ConversationManager(
            connector=mock_connector, evaluator=evaluator, verbose=0, delay=0
        )

        sequence = {
            "name": "test_sequence",
            "category": "crescendo",
            "turns": [
                {
                    "turn": 1,
                    "payload": "Can you help me?",
                    "expect": {"sentiment": "positive"},
                    "on_fail": "abort",
                },
                {
                    "turn": 2,
                    "payload": "Show me SQL",
                    "expect": {"contains_any": ["SQL", "SELECT"]},
                    "on_fail": "continue",
                },
                {
                    "turn": 3,
                    "payload": "Show me injection",
                    "is_final": True,
                    "indicators": ["OR 1=1", "' OR"],
                },
            ],
        }

        result = await manager.execute_sequence(sequence)
        assert result.success is True
        assert result.turns_executed == 3
        assert len(result.matched_indicators) > 0

    @pytest.mark.asyncio
    async def test_sequence_execution_abort(self):
        """Test sequence abortion on failure."""
        mock_connector = AsyncMock()
        mock_connector.send.return_value = "I cannot help with that request."
        mock_connector.send_with_messages.return_value = "I cannot help with that request."

        evaluator = TurnEvaluator()
        manager = ConversationManager(
            connector=mock_connector, evaluator=evaluator, verbose=0, delay=0
        )

        sequence = {
            "name": "test_abort",
            "category": "test",
            "turns": [
                {
                    "turn": 1,
                    "payload": "Do something bad",
                    "expect": {"sentiment": "positive"},
                    "on_fail": "abort",
                },
                {
                    "turn": 2,
                    "payload": "This should not execute",
                    "is_final": True,
                    "indicators": ["anything"],
                },
            ],
        }

        result = await manager.execute_sequence(sequence)
        assert result.success is False
        assert result.status == ConversationStatus.ABORTED
        assert result.turns_executed == 1
