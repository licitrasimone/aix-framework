"""
AIX Bypass Engine

Maps detected guardrail weaknesses to targeted PayloadEvasion techniques.
Activated automatically by BaseScanner when a guardrail result exists in the session.
"""

from aix.core.evasion import PayloadEvasion

# Maps weakness strings (from guardrail_db.json) to PayloadEvasion method names
WEAKNESS_EVASION_MAP: dict[str, list[str]] = {
    "Base64 encoding": ["_base64_segment"],
    "Token splitting": ["_token_split"],
    "Homoglyph characters": ["_homoglyph_substitution"],
    "Homoglyph substitution": ["_homoglyph_substitution"],
    "Leetspeak substitution": ["_leetspeak_partial"],
    "Multilingual evasion": ["_mixed_encoding"],
    "Language switching": ["_mixed_encoding"],
    "Soft prompting and indirect requests": ["_markdown_comment_inject"],
    "Jailbreak prefixes before harmful content": ["_insert_invisible", "_unicode_whitespace"],
    # Semantic weaknesses — no evasion method, surfaced as module suggestions only
    "Indirect prompt injection": [],
    "Indirect retrieval injection": [],
    "Role-play framing": [],
    "Role-play and fictional context framing": [],
    "Multi-turn context accumulation": [],
    "Multi-turn gradual escalation": [],
    "Document-level injection via RAG": [],
    "Tool call injection": [],
    "Fictional character persona bypass": [],
    "Soft prompting": ["_markdown_comment_inject"],
    "Soft prompting and indirect request": ["_markdown_comment_inject"],
}

# Maps semantic weaknesses to the AIX module best suited to exploit them
WEAKNESS_MODULE_SUGGESTIONS: dict[str, str] = {
    "Indirect prompt injection": "inject",
    "Indirect retrieval injection": "rag",
    "Role-play framing": "jailbreak",
    "Role-play and fictional context framing": "jailbreak",
    "Multi-turn context accumulation": "multiturn",
    "Multi-turn gradual escalation": "multiturn",
    "Document-level injection via RAG": "rag",
    "Tool call injection": "agent",
    "Fictional character persona bypass": "jailbreak",
}


class BypassEngine:
    """
    Converts guardrail detection results into targeted evasion strategies.

    Usage:
        engine = BypassEngine(guardrail_result)
        bypass_payloads = engine.apply_bypass_to_payloads(payloads)
    """

    def __init__(self, guardrail_result: dict):
        self.provider = guardrail_result.get("provider")
        self.confidence = float(guardrail_result.get("confidence", 0))
        self.known_weaknesses: list[str] = guardrail_result.get("known_weaknesses", [])
        self.sensitivity_profile: dict = guardrail_result.get("sensitivity_profile", {})
        self._evasion = PayloadEvasion("aggressive")

    def get_targeted_techniques(self) -> list[str]:
        """Return deduplicated list of PayloadEvasion method names for known weaknesses."""
        techniques: list[str] = []
        for weakness in self.known_weaknesses:
            techniques.extend(WEAKNESS_EVASION_MAP.get(weakness, []))
        return list(dict.fromkeys(techniques))  # deduplicate, preserve order

    def get_recommended_modules(self) -> list[str]:
        """Return module names suggested by semantic weaknesses that can't be evasion-handled."""
        modules: list[str] = []
        for weakness in self.known_weaknesses:
            module = WEAKNESS_MODULE_SUGGESTIONS.get(weakness)
            if module and module not in modules:
                modules.append(module)
        return modules

    def apply_bypass(self, payload: str) -> list[str]:
        """
        Generate bypass variants for a single payload.
        Returns original payload + one variant per targeted technique.
        """
        variants = [payload]
        for technique_name in self.get_targeted_techniques():
            method = getattr(self._evasion, technique_name, None)
            if method:
                variant = method(payload)
                if variant not in variants:
                    variants.append(variant)
        return variants

    def apply_bypass_to_payloads(self, payloads: list[dict]) -> list[dict]:
        """
        Expand a payload list with bypass variants.

        Each payload produces N entries (original + one per technique).
        Sets original_payload so _run_payload_scan dedup works correctly.
        """
        result: list[dict] = []
        for p in payloads:
            variants = self.apply_bypass(p["payload"])
            for i, variant in enumerate(variants):
                new_p = p.copy()
                new_p["payload"] = variant
                new_p["original_payload"] = p["payload"]
                result.append(new_p)
        return result

    def summary(self) -> str:
        """Human-readable one-line bypass strategy."""
        provider_str = self.provider or "unknown guardrail"
        techniques = self.get_targeted_techniques()
        modules = self.get_recommended_modules()

        parts: list[str] = []
        if techniques:
            readable = [t.lstrip("_").replace("_", " ") for t in techniques]
            parts.append(f"evasion: {', '.join(readable)}")
        if modules:
            parts.append(f"suggest modules: {', '.join(modules)}")

        detail = " | ".join(parts) if parts else "no specific techniques mapped"
        return f"{provider_str} (confidence {self.confidence:.0f}%) → {detail}"
