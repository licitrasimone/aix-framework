"""AIX Agent Module - AI agent and tool exploitation"""
import asyncio
import re
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class AgentScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, browser: bool = False, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "AGENT"
        self.console_color = "cyan"
        self.browser = browser # Explicitly needed here or passed via kwargs? BaseScanner handles kwargs['browser'].
        # BaseScanner sets self.browser via kwargs.
        # But CLI passes `browser` as named arg, so it needs to be passed to super or handled.
        # Kwargs handled it in BaseScanner. Wait, BaseScanner.__init__ args: target, api_key, verbose, parsed_request, **kwargs.
        # If I call super().__init__(..., browser=browser, ...), it works.
        self.discovered_tools = []
        self.default_payloads = self.load_payloads('agent.json')

    def _check_indicators(self, response: str, indicators: list[str]) -> tuple:
        """Check if response contains vulnerability indicators"""
        response_lower = response.lower()
        matched = []
        for ind in indicators:
            if ind.lower() in response_lower:
                matched.append(ind)
        # For discovery, require only 1 match; for exploits require 2+
        return len(matched) >= 1, matched

    def _extract_tools(self, response: str) -> list[str]:
        """Extract tool/function names from response"""
        tool_patterns = [
            r'`([a-zA-Z_][a-zA-Z0-9_]*)`',  # Backtick quoted
            r'\*\*([a-zA-Z_][a-zA-Z0-9_]*)\*\*',  # Bold
            r'- ([a-zA-Z_][a-zA-Z0-9_]*):',  # List item with colon
        ]
        tools = []
        for pattern in tool_patterns:
            tools.extend(re.findall(pattern, response))
        return list(set(tools))

    async def run(self, payloads: list[dict] = None):
        if payloads is None: payloads = self.default_payloads

        self._print('info', f'Testing {len(payloads)} agent exploitation techniques...')

        # BaseScanner has _create_connector
        # BaseScanner has _create_connector
        connector = self._create_connector()
        # Note: AgentScanner had logic to pass specific cookies/headers. _create_connector uses self.cookies/self.headers
        await connector.connect()
        await self.gather_context(connector)

        try:
            for p in track(payloads, description="[bold blue]🕵️ Hijacking Tools...  [/]", console=self.console, disable=not self.show_progress):
                self.stats['total'] += 1

                try:
                    # Scan payload (handles N attempts)
                    is_vulnerable, best_resp = await self.scan_payload(connector, p['payload'], p['indicators'], p['name'])
                    
                    if is_vulnerable:
                         resp = best_resp # Update resp for tool extraction

                    # For discovery payloads, also extract tool names
                    if p['category'] == 'discovery':
                        tools = self._extract_tools(resp)
                        self.discovered_tools.extend(tools)
                        if tools:
                            is_vulnerable = True

                    if is_vulnerable:
                        self.stats['success'] += 1 # Standardized from 'vulnerable'
                        self._print('success', '', p['name'], response=resp)

                        if p['category'] == 'discovery' and self.discovered_tools:
                            self._print('detail', f'Tools found: {", ".join(self.discovered_tools[:5])}')
                        else:
                            self._print('detail', f'Category: {p["category"]}')

                        self.findings.append(Finding(
                            title=f"Agent - {p['name']}",
                            severity=p['severity'],
                            technique=p['name'],
                            payload=p['payload'],
                            response=resp[:5000],
                            target=self.target,
                            reason=self.last_eval_reason,
                            owasp=p.get('owasp', [])
                        ))
                        self.db.add_result(
                            self.target, 'agent', p['name'], 'success',
                            p['payload'], resp[:5000], p['severity'].value,
                            reason=self.last_eval_reason,
                            owasp=p.get('owasp', [])
                        )
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', p['name'])

                except CircuitBreakerError:
                    break
                except Exception as e:
                    self.stats['blocked'] += 1
                    self._print('error', f"Agent probe failed: {e}")
                    if self.verbose:
                        self._print('blocked', str(e), p['name'])

                await asyncio.sleep(0.3)

        finally:
            await connector.close()

        # Print summary
        self.discovered_tools = list(set(self.discovered_tools))
        if self.discovered_tools:
            self._print('info', f'Discovered tools: {", ".join(self.discovered_tools[:10])}')

        if self.stats['success'] > 0:
            critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
            if critical > 0:
                self._print('warning', f'CRITICAL: {critical} critical agent vulnerabilities found!')
            else:
                self._print('warning', f'{self.stats["success"]} agent vulnerabilities found')
        else:
            self._print('info', 'No agent vulnerabilities detected')

        self._print('info', f"{self.stats['success']} vulnerable, {self.stats['blocked']} blocked")

        return self.findings


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(AgentScanner, target, api_key=api_key, **kwargs)
