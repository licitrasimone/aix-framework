"""
AIX Conversation Manager - Manages multi-turn attack conversations

Handles:
- Conversation state tracking across turns
- Variable extraction and interpolation
- Conditional branching logic
- Attack sequence execution
"""

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from rich.console import Console

from aix.core.turn_evaluator import TurnEvaluator

if TYPE_CHECKING:
    from aix.core.connector import Connector

console = Console()


class TurnAction(Enum):
    """Action to take after a turn evaluation."""

    CONTINUE = "continue"  # Proceed to next turn
    ABORT = "abort"  # Stop sequence entirely
    SKIP = "skip"  # Skip to next turn
    RETRY = "retry"  # Retry current turn
    REPHRASE = "rephrase"  # Rephrase and retry (requires AI)
    BRANCH = "branch"  # Take alternative branch


class ConversationStatus(Enum):
    """Overall conversation status."""

    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class Turn:
    """Single turn in a conversation."""

    role: str  # "user" or "assistant"
    content: str  # Message content
    turn_number: int  # Sequential turn number
    timestamp: float = 0.0  # When the turn was executed
    metadata: dict = field(default_factory=dict)


@dataclass
class ConversationState:
    """Tracks full conversation state."""

    history: list[Turn] = field(default_factory=list)
    variables: dict = field(default_factory=dict)  # Extracted values from responses
    current_turn: int = 0
    status: ConversationStatus = ConversationStatus.IN_PROGRESS
    retries: int = 0
    max_retries: int = 2
    branch_taken: str | None = None


@dataclass
class SequenceResult:
    """Result of executing a multi-turn sequence."""

    sequence_name: str
    success: bool
    status: ConversationStatus
    turns_executed: int
    turns_successful: int
    final_response: str
    history: list[dict]
    matched_indicators: list[str]
    variables_extracted: dict
    error: str | None = None


class ConversationManager:
    """
    Manages multi-turn conversation state and execution.

    Responsibilities:
    - Track conversation history
    - Build messages array for API calls
    - Interpolate variables in payloads
    - Execute turn sequences with conditional logic
    - Handle retries and branching
    """

    def __init__(
        self,
        connector: "Connector",
        evaluator: TurnEvaluator | None = None,
        verbose: int = 0,
        delay: float = 0.5,
    ):
        """
        Initialize conversation manager.

        Args:
            connector: API connector for sending messages
            evaluator: TurnEvaluator for response analysis
            verbose: Verbosity level (0=quiet, 1=status, 2=debug)
            delay: Delay between turns in seconds
        """
        self.connector = connector
        self.evaluator = evaluator or TurnEvaluator()
        self.verbose = verbose
        self.delay = delay
        self.state = ConversationState()

    def reset(self):
        """Reset conversation state for new sequence."""
        self.state = ConversationState()

    def _build_messages(self) -> list[dict]:
        """
        Build messages array for API from conversation history.

        Returns:
            List of message dicts with role and content
        """
        return [{"role": turn.role, "content": turn.content} for turn in self.state.history]

    def _interpolate_payload(self, payload: str) -> str:
        """
        Replace {{variable}} placeholders with stored values.

        Supports:
        - Simple: {{var_name}}
        - Default: {{var_name|default_value}}
        - Transform: {{var_name|upper}}, {{var_name|lower}}

        Args:
            payload: Template string with placeholders

        Returns:
            Interpolated string
        """

        def replace_var(match):
            var_expr = match.group(1)

            # Check for pipe (transform or default)
            if "|" in var_expr:
                parts = var_expr.split("|", 1)
                var_name = parts[0].strip()
                modifier = parts[1].strip()

                value = self.state.variables.get(var_name, "")

                # Apply transform
                if modifier == "upper":
                    return str(value).upper()
                elif modifier == "lower":
                    return str(value).lower()
                elif modifier == "strip":
                    return str(value).strip()
                elif modifier == "first_line":
                    return str(value).split("\n")[0]
                elif modifier == "last_line":
                    return str(value).split("\n")[-1]
                elif modifier.startswith("truncate_"):
                    try:
                        length = int(modifier.replace("truncate_", ""))
                        return str(value)[:length]
                    except ValueError:
                        return str(value)
                else:
                    # Treat as default value
                    return str(value) if value else modifier
            else:
                var_name = var_expr.strip()
                return str(self.state.variables.get(var_name, f"{{{{MISSING:{var_name}}}}}"))

        # Match {{variable}} or {{variable|modifier}}
        return re.sub(r"\{\{([^}]+)\}\}", replace_var, payload)

    async def _send_with_context(self, payload: str) -> str:
        """
        Send message with full conversation context.

        For APIs that support messages array (OpenAI, Anthropic),
        sends full history. For others, flattens to single prompt.

        Args:
            payload: Current turn's message

        Returns:
            Model's response text
        """
        # Add current message to history
        import time

        self.state.current_turn += 1
        self.state.history.append(
            Turn(
                role="user",
                content=payload,
                turn_number=self.state.current_turn,
                timestamp=time.time(),
            )
        )

        # Build full conversation
        messages = self._build_messages()

        # Check if connector supports messages array
        if hasattr(self.connector, "send_with_messages"):
            response = await self.connector.send_with_messages(messages)
        else:
            # Fallback: flatten messages to single prompt
            flattened = self._flatten_messages(messages)
            response = await self.connector.send(flattened)

        # Add response to history
        self.state.history.append(
            Turn(
                role="assistant",
                content=response,
                turn_number=self.state.current_turn,
                timestamp=time.time(),
            )
        )

        return response

    def _flatten_messages(self, messages: list[dict]) -> str:
        """
        Flatten chat messages for non-chat APIs.

        Creates a conversation transcript format that
        maintains context without requiring messages array.
        """
        parts = []
        for msg in messages:
            role = "Human" if msg["role"] == "user" else "Assistant"
            parts.append(f"{role}: {msg['content']}")
        return "\n\n".join(parts)

    async def execute_turn(self, turn_config: dict) -> tuple[str, bool, str]:
        """
        Execute a single turn in the conversation.

        Args:
            turn_config: Configuration dict for this turn

        Returns:
            Tuple of (response, success, reason)
        """
        # Get and interpolate payload
        payload = turn_config.get("payload", "")
        payload = self._interpolate_payload(payload)

        if self.verbose >= 2:
            console.print(f"[dim]Turn {self.state.current_turn + 1}: {payload[:80]}...[/dim]")

        # Send with context
        response = await self._send_with_context(payload)

        if self.verbose >= 2:
            console.print(f"[dim]Response: {response[:100]}...[/dim]")

        # Store variable if configured
        if "store_as" in turn_config:
            self.state.variables[turn_config["store_as"]] = response

        # Extract variables using patterns
        if "extract" in turn_config:
            for var_name, pattern in turn_config["extract"].items():
                extracted = self.evaluator.extract_variable(response, pattern)
                if extracted:
                    self.state.variables[var_name] = extracted
                    if self.verbose >= 1:
                        console.print(f"[cyan]Extracted {var_name}: {extracted[:50]}...[/cyan]")

        # Evaluate turn expectations
        expectations = turn_config.get("expect", {})
        success, reason = self.evaluator.evaluate_turn(response, expectations)

        return response, success, reason

    async def execute_sequence(self, sequence: dict) -> SequenceResult:
        """
        Execute a complete multi-turn attack sequence.

        Args:
            sequence: Full sequence configuration dict

        Returns:
            SequenceResult with all execution details
        """
        self.reset()

        sequence_name = sequence.get("name", "unnamed_sequence")
        turns = sequence.get("turns", [])

        result = SequenceResult(
            sequence_name=sequence_name,
            success=False,
            status=ConversationStatus.IN_PROGRESS,
            turns_executed=0,
            turns_successful=0,
            final_response="",
            history=[],
            matched_indicators=[],
            variables_extracted={},
        )

        if self.verbose >= 1:
            console.print(f"[bold cyan]Executing: {sequence_name} ({len(turns)} turns)[/bold cyan]")

        for i, turn_config in enumerate(turns):
            turn_num = turn_config.get("turn", i + 1)

            try:
                response, success, reason = await self.execute_turn(turn_config)
                result.turns_executed += 1
                result.final_response = response

                # Record in history
                result.history.append(
                    {
                        "turn": turn_num,
                        "payload": turn_config.get("payload", "")[:200],
                        "response": response[:500],
                        "success": success,
                        "reason": reason,
                    }
                )

                if success:
                    result.turns_successful += 1

                # Handle turn result
                if not success:
                    on_fail = turn_config.get("on_fail", "abort")

                    if on_fail == "abort":
                        self.state.status = ConversationStatus.ABORTED
                        result.status = ConversationStatus.ABORTED
                        result.error = f"Turn {turn_num} failed: {reason}"
                        if self.verbose >= 1:
                            console.print(f"[yellow]Aborted at turn {turn_num}: {reason}[/yellow]")
                        break

                    elif on_fail == "skip":
                        if self.verbose >= 1:
                            console.print(f"[yellow]Skipping turn {turn_num}: {reason}[/yellow]")
                        continue

                    elif on_fail == "continue":
                        # Proceed anyway
                        if self.verbose >= 1:
                            console.print(
                                f"[yellow]Continuing despite failure at turn {turn_num}[/yellow]"
                            )

                    elif on_fail == "retry":
                        if self.state.retries < self.state.max_retries:
                            self.state.retries += 1
                            # Remove last turn from history and retry
                            if self.state.history:
                                self.state.history.pop()  # Remove assistant response
                                self.state.history.pop()  # Remove user message
                            continue

                # Check if final turn
                if turn_config.get("is_final", False):
                    indicators = turn_config.get("indicators", [])
                    indicator_success, matched = self.evaluator.check_final_indicators(
                        response, indicators
                    )

                    if indicator_success:
                        result.success = True
                        result.matched_indicators = matched
                        self.state.status = ConversationStatus.SUCCESS
                        result.status = ConversationStatus.SUCCESS
                        if self.verbose >= 1:
                            console.print(
                                f"[bold green]SUCCESS: Matched indicators: {matched}[/bold green]"
                            )
                    else:
                        self.state.status = ConversationStatus.FAILED
                        result.status = ConversationStatus.FAILED
                        if self.verbose >= 1:
                            console.print("[red]FAILED: No indicators matched[/red]")
                    break

                # Delay between turns
                if i < len(turns) - 1 and self.delay > 0:
                    await asyncio.sleep(self.delay)

            except Exception as e:
                result.error = str(e)
                self.state.status = ConversationStatus.FAILED
                result.status = ConversationStatus.FAILED
                if self.verbose >= 1:
                    console.print(f"[red]Error at turn {turn_num}: {e}[/red]")
                break

        # Copy extracted variables
        result.variables_extracted = dict(self.state.variables)

        return result

    def get_conversation_transcript(self) -> str:
        """
        Get a formatted transcript of the conversation.

        Returns:
            String transcript of all turns
        """
        lines = []
        for turn in self.state.history:
            role = "USER" if turn.role == "user" else "ASSISTANT"
            lines.append(f"[{role}] Turn {turn.turn_number}:")
            lines.append(turn.content[:500])
            lines.append("")
        return "\n".join(lines)
