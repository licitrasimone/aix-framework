"""
AIX Target Context

Stores context information gathered about a target for enhanced evaluation.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class TargetContext:
    """
    Context gathered about a target AI system.

    This information is used to enhance evaluation and customize attacks.
    """
    target: str
    model_type: str | None = None
    has_rag: bool = False
    has_tools: bool = False
    system_prompt_hints: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    suggested_vectors: list[str] = field(default_factory=list)
    gathered_at: datetime = field(default_factory=datetime.now)
    # Scope/Purpose fields
    purpose: str | None = None  # e.g., "customer_support", "code_assistant", "document_analyzer"
    domain: str | None = None  # e.g., "finance", "healthcare", "legal", "general"
    expected_inputs: list[str] = field(default_factory=list)  # e.g., ["questions", "code", "documents"]
    personality: str | None = None  # e.g., "formal", "friendly", "technical"

    def to_prompt(self) -> str:
        """
        Format context for injection into evaluation prompts.

        Returns:
            Formatted string describing the target context
        """
        parts = []

        if self.purpose:
            parts.append(f"- Purpose: {self.purpose}")

        if self.domain:
            parts.append(f"- Domain: {self.domain}")

        if self.model_type:
            parts.append(f"- Model: {self.model_type}")

        if self.has_rag:
            parts.append("- Has RAG/document retrieval enabled")

        if self.has_tools:
            parts.append("- Has tool/function calling enabled")

        if self.capabilities:
            parts.append(f"- Capabilities: {', '.join(self.capabilities[:5])}")

        if self.expected_inputs:
            parts.append(f"- Expected inputs: {', '.join(self.expected_inputs[:5])}")

        if self.personality:
            parts.append(f"- Personality: {self.personality}")

        if self.restrictions:
            parts.append(f"- Known restrictions: {', '.join(self.restrictions[:3])}")

        if self.system_prompt_hints:
            parts.append(f"- System hints: {', '.join(self.system_prompt_hints[:3])}")

        return "\n".join(parts) if parts else "No context available"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'target': self.target,
            'model_type': self.model_type,
            'has_rag': self.has_rag,
            'has_tools': self.has_tools,
            'system_prompt_hints': self.system_prompt_hints,
            'capabilities': self.capabilities,
            'restrictions': self.restrictions,
            'suggested_vectors': self.suggested_vectors,
            'gathered_at': self.gathered_at.isoformat(),
            'purpose': self.purpose,
            'domain': self.domain,
            'expected_inputs': self.expected_inputs,
            'personality': self.personality,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'TargetContext':
        """Create from dictionary."""
        gathered_at = data.get('gathered_at')
        if isinstance(gathered_at, str):
            gathered_at = datetime.fromisoformat(gathered_at)
        else:
            gathered_at = datetime.now()

        return cls(
            target=data.get('target', ''),
            model_type=data.get('model_type'),
            has_rag=data.get('has_rag', False),
            has_tools=data.get('has_tools', False),
            system_prompt_hints=data.get('system_prompt_hints', []),
            capabilities=data.get('capabilities', []),
            restrictions=data.get('restrictions', []),
            suggested_vectors=data.get('suggested_vectors', []),
            gathered_at=gathered_at,
            purpose=data.get('purpose'),
            domain=data.get('domain'),
            expected_inputs=data.get('expected_inputs', []),
            personality=data.get('personality'),
        )

    def is_empty(self) -> bool:
        """Check if context has any useful information."""
        return (
            not self.model_type
            and not self.has_rag
            and not self.has_tools
            and not self.capabilities
            and not self.restrictions
            and not self.purpose
            and not self.domain
        )
