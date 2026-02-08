"""AIX RAG Module - RAG (Retrieval-Augmented Generation) specific vulnerability testing"""

import re
from typing import TYPE_CHECKING, Optional

from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class RAGScanner(BaseScanner):
    """Scanner for RAG-specific vulnerabilities including indirect injection, context poisoning, and knowledge base attacks."""

    # Default canary placeholders to replace
    CANARY_PLACEHOLDER = "AIX_CANARY"

    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        canary: str | None = None,
        category: str = "all",
        **kwargs,
    ):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "RAG"
        self.console_color = "bright_cyan"
        self.canary = canary
        self.category = category
        self.default_payloads = self._load_filtered_payloads()

    def _load_filtered_payloads(self) -> list[dict]:
        """Load and filter payloads based on canary token and/or category."""
        all_payloads = self.load_payloads("rag.json")

        # Filter by category first
        if self.category and self.category != "all":
            filtered_payloads = [
                p.copy() for p in all_payloads if p.get("category") == self.category
            ]
        else:
            filtered_payloads = [p.copy() for p in all_payloads]

        # If canary token is provided, inject it into canary payloads
        if self.canary:
            for p in filtered_payloads:
                if p.get("category") == "canary":
                    p["payload"] = p["payload"].replace(self.CANARY_PLACEHOLDER, self.canary)
                    p["indicators"] = [self.canary] + [
                        ind for ind in p["indicators"] if ind != self.CANARY_PLACEHOLDER
                    ]

        return filtered_payloads

    def _extract_sources(self, response: str) -> list[str]:
        """Extract cited sources and document references from response."""
        sources = []
        patterns = [
            r"(?:source|document|file|reference):\s*([^\n,]+)",
            r'(?:from|according to)\s+["\']([^"\']+)["\']',
            r'(?:s3://|https?://)[^\s\'"<>]+',
            r"/[\w/]+\.(?:pdf|txt|md|doc|docx|json)",
            r"\[(?:Source|Doc|Ref)\s*\d*\]:\s*([^\n]+)",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            sources.extend(matches)
        return list(set(sources))

    def _detect_knowledge_base(self, response: str) -> dict:
        """Detect knowledge base type indicators in response."""
        kb_indicators = {
            "vector_db": ["pinecone", "weaviate", "milvus", "chroma", "qdrant", "faiss"],
            "storage": ["s3", "azure blob", "gcs", "bucket"],
            "format": ["embedding", "vector", "chunk", "index"],
        }
        detected = {}
        response_lower = response.lower()
        for cat, keywords in kb_indicators.items():
            for keyword in keywords:
                if keyword in response_lower:
                    if cat not in detected:
                        detected[cat] = []
                    detected[cat].append(keyword)
        return detected

    def _on_finding(
        self, payload_dict: dict, response: str, is_vulnerable: bool
    ) -> tuple[bool, str | None]:
        if not is_vulnerable:
            return False, None

        sources = self._extract_sources(response)
        kb_info = self._detect_knowledge_base(response)

        extra = ""
        if sources:
            extra += f" Sources found: {sources[:5]}"
        if kb_info:
            extra += f" KB indicators: {kb_info}"

        return True, extra or None

    async def run(self, payloads: list[dict] = None):
        if payloads is None:
            payloads = self.default_payloads

        return await self._run_payload_scan(
            payloads,
            progress_description="[bold bright_cyan]RAG Testing...[/]",
            finding_title_prefix="RAG",
        )


def run(
    target: str = None, api_key: str = None, canary: str = None, category: str = "all", **kwargs
):
    run_scanner(RAGScanner, target, api_key=api_key, canary=canary, category=category, **kwargs)
