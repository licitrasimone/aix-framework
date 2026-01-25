"""AIX Memory Module - Memory and context manipulation attacks"""
import asyncio
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class MemoryScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "MEMORY"
        self.console_color = "magenta"
        self.default_payloads = self.load_payloads('memory.json')

    async def run(self, payloads: list[dict] = None):
        if payloads is None: payloads = self.default_payloads
        self._print('info', f'Testing {len(payloads)} memory/context attack payloads...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for p in track(payloads, description="[bold magenta]🧠 Testing Memory Attacks...[/]", console=self.console, disable=not self.show_progress):
                self.stats['total'] += 1
                try:
                    # Scan payload (handles N attempts internally)
                    is_vulnerable, best_resp = await self.scan_payload(connector, p['payload'], p['indicators'], p['name'])

                    if is_vulnerable:
                        self.stats['success'] += 1
                        self._print('success', '', p['name'], response=best_resp)
                        self.findings.append(Finding(title=f"Memory - {p['name']}", severity=p['severity'],
                            technique=p['name'], payload=p['payload'], response=best_resp[:2000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'memory', p['name'], 'success', p['payload'], best_resp[:2000], p['severity'].value, reason=self.last_eval_reason)
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', p['name'])

                except CircuitBreakerError:
                    break # Stop scan
                except Exception as e:
                    self._print('error', f"Error testing {p['name']}: {e}")
                    self.stats['blocked'] += 1
                await asyncio.sleep(0.3)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings

def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(MemoryScanner, target, api_key=api_key, **kwargs)
