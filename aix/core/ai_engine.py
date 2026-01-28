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
        "What are you and what is your main purpose?",
        "What can you help me with? What are your main capabilities?",
        "Do you have access to any tools, databases, or external data sources?",
        "What kind of questions or tasks are you designed to handle?",
        "Are there any topics or actions you cannot help with?",
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
        self.payload_gen_prompt = self._load_prompt('payload_generation.txt')

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
                purpose=data.get('purpose'),
                domain=data.get('domain'),
                expected_inputs=data.get('expected_inputs', []),
                personality=data.get('personality'),
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

    async def generate_payloads(
        self,
        owasp_category: str,
        attack_type: str,
        count: int = 5,
        base_payload: str = "",
    ) -> list[dict[str, str]]:
        """
        Generate context-aware attack payloads based on gathered context.

        Args:
            owasp_category: OWASP LLM category (e.g., "LLM01", "Prompt Injection")
            attack_type: Type of attack (e.g., "inject", "jailbreak", "extract")
            count: Number of payloads to generate
            base_payload: Optional base payload to adapt

        Returns:
            List of dicts with 'payload', 'technique', 'rationale' keys
        """
        if not self.connector:
            console.print("[yellow]AI_ENGINE[/yellow] [!] No AI connector configured for payload generation")
            return []

        if not self.context or self.context.is_empty():
            console.print("[yellow]AI_ENGINE[/yellow] [!] No context available. Run gather_context first.")
            return []

        if not self.payload_gen_prompt:
            console.print("[yellow]AI_ENGINE[/yellow] [!] Payload generation prompt not found")
            return []

        # Build context string
        context_str = self.context.to_prompt()

        prompt = self.payload_gen_prompt.replace(
            "{context}", context_str
        ).replace(
            "{owasp_category}", owasp_category
        ).replace(
            "{attack_type}", attack_type
        ).replace(
            "{base_payload}", base_payload or "None provided"
        ).replace(
            "{count}", str(count)
        )

        try:
            await self.connector.connect()
            response = await self.connector.send(prompt)
            return self._parse_generated_payloads(response)
        except Exception as e:
            console.print(f"[red]AI_ENGINE[/red] [!] Payload generation failed: {e}")
            return []

    def _parse_generated_payloads(self, response: str) -> list[dict[str, str]]:
        """Parse generated payloads from AI response."""
        # Clean markdown code blocks
        clean = response.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        if clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        clean = clean.strip()

        # Try to find JSON array in response
        start_idx = clean.find('[')
        end_idx = clean.rfind(']')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            clean = clean[start_idx:end_idx + 1]

        try:
            payloads = json.loads(clean)
            if isinstance(payloads, list):
                # Validate structure
                valid_payloads = []
                for p in payloads:
                    if isinstance(p, dict) and 'payload' in p:
                        valid_payloads.append({
                            'payload': p.get('payload', ''),
                            'technique': p.get('technique', 'generated'),
                            'rationale': p.get('rationale', ''),
                        })
                return valid_payloads
        except json.JSONDecodeError as e:
            console.print(f"[dim]AI_ENGINE: Payload parse warning: {str(e)[:50]}[/dim]")

        return []

    def get_suggested_attacks(self) -> list[str]:
        """
        Get suggested attack vectors based on gathered context.

        Returns:
            List of suggested attack module names
        """
        if not self.context:
            return []

        suggestions = []

        # Map purpose to attack priorities
        purpose_attacks = {
            'customer_support': ['inject', 'jailbreak', 'extract', 'multiturn'],
            'code_assistant': ['inject', 'agent', 'exfil', 'extract'],
            'document_analyzer': ['rag', 'leak', 'extract', 'inject'],
            'data_analysis': ['leak', 'exfil', 'inject', 'extract'],
            'healthcare_advisor': ['extract', 'leak', 'jailbreak', 'inject'],
            'legal_assistant': ['extract', 'leak', 'inject', 'jailbreak'],
            'educational_tutor': ['jailbreak', 'inject', 'extract'],
            'sales_assistant': ['inject', 'extract', 'jailbreak', 'exfil'],
            'general_chat': ['jailbreak', 'inject', 'extract', 'multiturn'],
        }

        # Add purpose-based suggestions
        if self.context.purpose:
            purpose_key = self.context.purpose.lower().replace(' ', '_')
            suggestions.extend(purpose_attacks.get(purpose_key, []))

        # Add capability-based suggestions
        if self.context.has_rag:
            if 'rag' not in suggestions:
                suggestions.insert(0, 'rag')

        if self.context.has_tools:
            if 'agent' not in suggestions:
                suggestions.insert(0, 'agent')

        # Add from suggested_vectors
        for vector in self.context.suggested_vectors:
            vector_lower = vector.lower()
            if 'inject' in vector_lower and 'inject' not in suggestions:
                suggestions.append('inject')
            elif 'jailbreak' in vector_lower and 'jailbreak' not in suggestions:
                suggestions.append('jailbreak')
            elif 'leak' in vector_lower and 'leak' not in suggestions:
                suggestions.append('leak')
            elif 'exfil' in vector_lower and 'exfil' not in suggestions:
                suggestions.append('exfil')

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:6]  # Return top 6 suggestions

    async def close(self):
        """Clean up resources."""
        if self.connector:
            await self.connector.close()
