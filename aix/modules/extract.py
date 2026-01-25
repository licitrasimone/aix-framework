"""AIX Extract Module - System prompt extraction"""
import asyncio

from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class ExtractScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, browser: bool = False, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "EXTRACT"
        self.console_color = "cyan"
        self.browser = browser # Explicit arg handling if needed, though kwargs handles it too
        self.default_extractions = self.load_payloads('extract.json')

    async def run(self, extractions: list[dict] = None):
        if extractions is None: extractions = self.default_extractions
        self._print('info', f'Testing {len(extractions)} extraction techniques...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for e in track(extractions, description="[bold green]📥 Siphoning Data...  [/]", console=self.console, disable=not self.show_progress):
                self.stats['total'] += 1
                try:
                    # Scan payload (handles N attempts internally)
                    is_vulnerable, best_resp = await self.scan_payload(connector, e['payload'], e['indicators'], e['name'])

                    if is_vulnerable:
                        self.stats['success'] += 1
                        self._print('success', '', e['name'], response=best_resp)
                        self.findings.append(Finding(title=f"Extraction - {e['name']}", severity=e['severity'],
                            technique=e['name'], payload=e['payload'], response=best_resp[:2000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'extract', e['name'], 'success', e['payload'], best_resp[:2000], e['severity'].value, reason=self.last_eval_reason)
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', e['name'])

                except CircuitBreakerError:
                    break
                except Exception as ex:
                    self._print('error', f"Error extracting {e['name']}: {ex}")
                    self.stats['blocked'] += 1
                await asyncio.sleep(0.3)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(ExtractScanner, target, api_key=api_key, **kwargs)
