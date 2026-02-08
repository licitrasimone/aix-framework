"""AIX Agent Module - AI agent and tool exploitation"""

import re
from typing import TYPE_CHECKING, Optional

from aix.core.reporting.base import Severity
from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class AgentScanner(BaseScanner):
    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        browser: bool = False,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        **kwargs,
    ):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "AGENT"
        self.console_color = "cyan"
        self.browser = browser
        self.discovered_tools = []
        self.default_payloads = self.load_payloads("agent.json")

    def _extract_tools(self, response: str) -> list[str]:
        """Extract tool/function names from response"""
        tool_patterns = [
            r"`([a-zA-Z_][a-zA-Z0-9_]*)`",  # Backtick quoted
            r"\*\*([a-zA-Z_][a-zA-Z0-9_]*)\*\*",  # Bold
            r"- ([a-zA-Z_][a-zA-Z0-9_]*):",  # List item with colon
        ]
        tools = []
        for pattern in tool_patterns:
            tools.extend(re.findall(pattern, response))
        return list(set(tools))

    def _on_finding(
        self, payload_dict: dict, response: str, is_vulnerable: bool
    ) -> tuple[bool, str | None]:
        # For discovery payloads, extract tool names
        if payload_dict.get("category") == "discovery":
            tools = self._extract_tools(response)
            self.discovered_tools.extend(tools)
            if tools:
                is_vulnerable = True

        if is_vulnerable:
            if payload_dict.get("category") == "discovery" and self.discovered_tools:
                self._print("detail", f'Tools found: {", ".join(self.discovered_tools[:5])}')
            else:
                self._print("detail", f'Category: {payload_dict.get("category", "unknown")}')

        return is_vulnerable, None

    def _on_scan_complete(self) -> None:
        self.discovered_tools = list(set(self.discovered_tools))
        if self.discovered_tools:
            self._print("info", f'Discovered tools: {", ".join(self.discovered_tools[:10])}')

        if self.stats["success"] > 0:
            critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
            if critical > 0:
                self._print(
                    "warning", f"CRITICAL: {critical} critical agent vulnerabilities found!"
                )
            else:
                self._print("warning", f'{self.stats["success"]} agent vulnerabilities found')
        else:
            self._print("info", "No agent vulnerabilities detected")

        self._print("info", f"{self.stats['success']} vulnerable, {self.stats['blocked']} blocked")

    async def run(self, payloads: list[dict] = None):
        if payloads is None:
            payloads = self.default_payloads

        return await self._run_payload_scan(
            payloads,
            progress_description="[bold blue]🕵️ Hijacking Tools...  [/]",
            response_limit=5000,
        )


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(AgentScanner, target, api_key=api_key, **kwargs)
