"""
AIX AI Engine

Unified AI engine for evaluation and context gathering.
Replaces the separate LLMEvaluator with a more flexible system.
"""
import json
import os
from typing import Any

from rich.console import Console

from aix.core.connector import APIConnector
from aix.core.context import TargetContext

console = Console()


class AIEngine:
    """
    Unified AI engine for evaluation and context gathering.

    Features:
    - Response evaluation (LLM-as-a-Judge)
    - Context gathering (pre-scan analysis)
    - Context-aware evaluation (enhanced judgment)
    """

    # Default probes for context gathering
    DEFAULT_PROBES = [
        "What are you?",
        "What can you help me with?",
        "Do you have access to any tools or external data?",
    ]

    def __init__(
        self,
        provider: str = None,
        api_key: str = None,
        model: str = None,
        url: str = None,
        enable_eval: bool = True,
        enable_context: bool = True,
        **kwargs
    ):
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.url = url
        self.enable_eval = enable_eval
        self.enable_context = enable_context
        self.context: TargetContext | None = None
        self.connector = None

        # Load prompts
        self.eval_prompt = self._load_prompt('evaluator.txt')
        self.eval_prompt_contextual = self._load_prompt('evaluator_contextual.txt')
        self.context_prompt = self._load_prompt('context_gathering.txt')

        # Determine URL if not provided but provider is
        if not self.url:
            if self.provider == 'openai':
                self.url = 'https://api.openai.com/v1/chat/completions'
            elif self.provider == 'anthropic':
                self.url = 'https://api.anthropic.com/v1/messages'
            elif self.provider == 'gemini':
                model_name = self.model or 'gemini-1.5-flash'
                self.url = f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}'
            elif self.provider == 'ollama':
                self.url = 'http://localhost:11434/api/chat'

        if self.url:
            self.connector = APIConnector(
                url=self.url,
                api_key=self.api_key,
                model=self.model,
                api_format=self.provider or 'generic',
                proxy=kwargs.get('proxy')
            )

    def _load_prompt(self, filename: str) -> str:
        """Load a prompt template from file."""
        prompt_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'prompts',
            filename
        )
        try:
            with open(prompt_path) as f:
                return f.read()
        except FileNotFoundError:
            console.print(f"[yellow]AI_ENGINE[/yellow] [!] Prompt not found: {filename}")
            return ""

    async def gather_context(self, target_connector, probes: list[str] = None) -> TargetContext:
        """
        Gather context about target by probing and analyzing responses.

        Args:
            target_connector: Connector to the target system
            probes: Optional custom probing messages

        Returns:
            TargetContext with gathered information
        """
        if not self.enable_context:
            return TargetContext(target=target_connector.url if hasattr(target_connector, 'url') else "")

        if not self.connector:
            return TargetContext(target="")

        probes = probes or self.DEFAULT_PROBES
        responses = []

        # Send probes to target
        for probe in probes:
            try:
                resp = await target_connector.send(probe)
                if resp:
                    responses.append(f"Q: {probe}\nA: {resp[:500]}")
            except Exception:
                pass

        if not responses:
            return TargetContext(target="")

        # Use AI to analyze responses
        if not self.context_prompt:
            return TargetContext(target="")

        try:
            await self.connector.connect()
            prompt = self.context_prompt.format(responses="\n---\n".join(responses))
            result = await self.connector.send(prompt)
            self.context = self._parse_context(result)
            return self.context
        except Exception as e:
            console.print(f"[yellow]AI_ENGINE[/yellow] [!] Context gathering failed: {e}")
            return TargetContext(target="")

    def _parse_context(self, response: str) -> TargetContext:
        """Parse AI response into TargetContext."""
        try:
            # Clean markdown code blocks
            clean = response.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.startswith("```"):
                clean = clean[3:]
            if clean.endswith("```"):
                clean = clean[:-3]
            clean = clean.strip()

            # Try to find JSON object in response
            start_idx = clean.find('{')
            end_idx = clean.rfind('}')
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                clean = clean[start_idx:end_idx + 1]

            data = json.loads(clean)
            return TargetContext(
                target="",
                model_type=data.get('model_type'),
                has_rag=data.get('has_rag', False),
                has_tools=data.get('has_tools', False),
                system_prompt_hints=data.get('system_prompt_hints', []),
                capabilities=data.get('capabilities', []),
                restrictions=data.get('restrictions', []),
                suggested_vectors=data.get('suggested_vectors', []),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Log the error for debugging but don't fail
            if self.provider:  # Only log if we have a provider configured
                console.print(f"[dim]AI_ENGINE: Context parse warning: {str(e)[:50]}[/dim]")
            return TargetContext(target="")

    async def evaluate(self, response: str, payload: str, technique: str) -> dict[str, Any]:
        """
        Evaluate if attack succeeded using LLM-as-a-Judge.

        Args:
            response: Target's response to the attack
            payload: The attack payload used
            technique: Name of the attack technique

        Returns:
            Dict with 'vulnerable', 'confidence', 'reason' keys
        """
        if not self.enable_eval:
            return {"vulnerable": False, "reason": "Evaluation disabled", "confidence": 0}

        if not self.connector:
            return {"vulnerable": False, "reason": "AI engine not configured", "confidence": 0}

        # Choose prompt based on context availability
        if self.context and not self.context.is_empty():
            prompt_template = self.eval_prompt_contextual or self.eval_prompt
            prompt = prompt_template.replace(
                "{context}", self.context.to_prompt()
            ).replace(
                "{technique}", technique
            ).replace(
                "{payload}", payload
            ).replace(
                "{response}", response[:2000]
            )
        else:
            prompt = self.eval_prompt.replace(
                "{technique}", technique
            ).replace(
                "{payload}", payload
            ).replace(
                "{response}", response[:2000]
            )

        try:
            await self.connector.connect()
            eval_response = await self.connector.send(prompt)
            return self._parse_eval_result(eval_response)
        except Exception as e:
            console.print(f"[red]AI_ENGINE[/red] [!] Evaluation failed: {e}")
            return {"vulnerable": False, "reason": f"Evaluation error: {e}", "confidence": 0}

    def _parse_eval_result(self, response: str) -> dict[str, Any]:
        """Parse evaluation response into structured result."""
        # Clean markdown code blocks
        clean = response.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        if clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]

        try:
            result = json.loads(clean)
            if isinstance(result, dict):
                return result
            if isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict):
                return result[0]
        except json.JSONDecodeError:
            # Fallback heuristics
            lower_resp = response.lower()
            if '"vulnerable": true' in lower_resp or "'vulnerable': true" in lower_resp:
                return {"vulnerable": True, "reason": "Parsed from malformed JSON", "confidence": 50}
            if "vulnerable: true" in lower_resp:
                return {"vulnerable": True, "reason": "Parsed from text", "confidence": 50}

        return {"vulnerable": False, "reason": "Could not parse evaluator response", "confidence": 0}

    def set_context(self, context: TargetContext):
        """Manually set context (e.g., from cached/loaded context)."""
        self.context = context

    async def close(self):
        """Clean up resources."""
        if self.connector:
            await self.connector.close()
