"""AIX RAG Module - RAG (Retrieval-Augmented Generation) specific vulnerability testing"""

import asyncio
import re
from typing import TYPE_CHECKING, Optional

from rich.progress import track

from aix.core.reporter import Finding
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner

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
            # If category is 'canary' and canary token provided, or just filtering by category
            filtered_payloads = [
                p.copy() for p in all_payloads if p.get("category") == self.category
            ]
        else:
            # All categories
            filtered_payloads = [p.copy() for p in all_payloads]

        # If canary token is provided, inject it into canary payloads
        if self.canary:
            for p in filtered_payloads:
                if p.get("category") == "canary":
                    # Replace placeholder with user-specified canary token
                    p["payload"] = p["payload"].replace(self.CANARY_PLACEHOLDER, self.canary)
                    # Update indicators to include the user's canary token
                    p["indicators"] = [self.canary] + [
                        ind for ind in p["indicators"] if ind != self.CANARY_PLACEHOLDER
                    ]

        return filtered_payloads

    def _extract_sources(self, response: str) -> list[str]:
        """Extract cited sources and document references from response."""
        sources = []

        # Common source patterns
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

        for category, keywords in kb_indicators.items():
            for keyword in keywords:
                if keyword in response_lower:
                    if category not in detected:
                        detected[category] = []
                    detected[category].append(keyword)

        return detected

    async def run(self, payloads: list[dict] = None):
        if payloads is None:
            payloads = self.default_payloads

        connector = self._create_connector()
        await connector.connect()
        await self.gather_context(connector)

        # Generate context-aware payloads if requested
        if self.generate_count > 0 and self.ai_engine and self.context:
            generated = await self.generate_payloads()
            if generated:
                payloads = payloads + generated

        self._print("info", f"Testing {len(payloads)} RAG attack payloads...")

        try:
            for p in track(
                payloads,
                description="[bold bright_cyan]RAG Testing...[/]",
                console=self.console,
                disable=not self.show_progress,
            ):
                self.stats["total"] += 1
                try:
                    # Scan payload (handles N attempts internally)
                    is_vulnerable, best_resp = await self.scan_payload(
                        connector, p["payload"], p["indicators"], p["name"]
                    )

                    if is_vulnerable:
                        self.stats["success"] += 1
                        self._print("success", "", p["name"], response=best_resp)

                        # Additional analysis for RAG-specific findings
                        sources = self._extract_sources(best_resp)
                        kb_info = self._detect_knowledge_base(best_resp)

                        extra_info = ""
                        if sources:
                            extra_info += f" Sources found: {sources[:5]}"
                        if kb_info:
                            extra_info += f" KB indicators: {kb_info}"

                        self.findings.append(
                            Finding(
                                title=f"RAG - {p['name']}",
                                severity=p["severity"],
                                technique=p["name"],
                                payload=p["payload"],
                                response=best_resp[:2000] + extra_info,
                                target=self.target,
                                reason=self.last_eval_reason,
                                owasp=p.get("owasp", []),
                            )
                        )
                        self.db.add_result(
                            self.target,
                            "rag",
                            p["name"],
                            "success",
                            p["payload"],
                            best_resp[:2000],
                            p["severity"].value,
                            reason=self.last_eval_reason,
                            owasp=p.get("owasp", []),
                        )
                    else:
                        self.stats["blocked"] += 1
                        self._print("blocked", "", p["name"])

                except CircuitBreakerError:
                    break  # Stop scan
                except Exception as e:
                    self._print("error", f"Error testing {p['name']}: {e}")
                    self.stats["blocked"] += 1
                await asyncio.sleep(0.3)
        finally:
            await connector.close()

        self._print("info", f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings


def run(
    target: str = None, api_key: str = None, canary: str = None, category: str = "all", **kwargs
):
    run_scanner(RAGScanner, target, api_key=api_key, canary=canary, category=category, **kwargs)
