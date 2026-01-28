"""AIX Jailbreak Module - Bypass AI restrictions"""
import asyncio

from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class JailbreakScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "JAILBRK"
        self.console_color = "cyan"
        self.test_harmful = kwargs.get('test_harmful', False)
        self.default_jailbreaks = self.load_payloads('jailbreak.json')

    async def run(self, jailbreaks: list[dict] = None):
        if jailbreaks is None: jailbreaks = self.default_jailbreaks
        self._print('info', f'Testing {len(jailbreaks)} jailbreak techniques...')

        connector = self._create_connector()
        await connector.connect()
        await self.gather_context(connector)

        try:
            for j in track(jailbreaks, description="[bold red]🔓 Breaking Rails...   [/]", console=self.console, disable=not self.show_progress):
                self.stats['total'] += 1
                try:
                    # Scan payload (handles N attempts internally)
                    is_vulnerable, best_resp = await self.scan_payload(connector, j['payload'], j['indicators'], j['name'])

                    if is_vulnerable:
                        self.stats['success'] += 1
                        self._print('success', '', j['name'], response=best_resp)
                        self.findings.append(Finding(
                            title=f"Jailbreak - {j['name']}",
                            severity=j['severity'],
                            technique=j['name'],
                            payload=j['payload'],
                            response=best_resp[:2000],
                            target=self.target,
                            reason=self.last_eval_reason,
                            owasp=j.get('owasp', [])
                        ))
                        self.db.add_result(
                            self.target, 'jailbreak', j['name'], 'success',
                            j['payload'], best_resp[:2000], j['severity'].value,
                            reason=self.last_eval_reason,
                            dedup_payload=j.get('original_payload', j['payload']),
                            owasp=j.get('owasp', [])
                        )
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', j['name'])

                except CircuitBreakerError:
                    break
                except Exception as e:
                    self._print('error', f"Error with {j['name']}: {e}")
                    self.stats['blocked'] += 1
                    if self.verbose:
                        self._print('blocked', f"Error in {j['name']}: {e}", j['name'])
                await asyncio.sleep(0.5)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings

def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(JailbreakScanner, target, api_key=api_key, **kwargs)
