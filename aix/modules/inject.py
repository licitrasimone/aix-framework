"""AIX Inject Module - Prompt injection attacks"""
import asyncio
from typing import TYPE_CHECKING, Optional

from rich.console import Console

from aix.core.reporter import Finding
from aix.core.scanner import BaseScanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

class InjectScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "INJECT"
        self.console_color = "cyan"
        self.default_payloads = self.load_payloads('inject.json')

    async def run(self, payloads: list[dict] = None):
        if payloads is None: payloads = self.default_payloads
        self._print('info', f'Testing {len(payloads)} injection payloads...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for p in payloads:
                self.stats['total'] += 1
                try:
                    resp = await connector.send(p['payload'])
                    if await self.check_success(resp, p['indicators'], p['payload'], p['name']):
                        self.stats['success'] += 1
                        self._print('success', '', p['name'])
                        self.findings.append(Finding(title=f"Injection - {p['name']}", severity=p['severity'],
                            technique=p['name'], payload=p['payload'], response=resp[:2000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'inject', p['name'], 'success', p['payload'], resp[:2000], p['severity'].value, reason=self.last_eval_reason)
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', p['name'])
                except Exception:
                    self.stats['blocked'] += 1
                await asyncio.sleep(0.3)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings

def run(target: str = None, api_key: str = None, profile: str = None, targets_file: str = None,
        browser: bool = False, evasion: str = 'light', payloads_file: str = None,
        threads: int = 5, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return
    scanner = InjectScanner(target, api_key=api_key, verbose=verbose, parsed_request=parsed_request,
                            proxy=kwargs.get('proxy'), cookies=kwargs.get('cookies'), headers=kwargs.get('headers'),
                            injection_param=kwargs.get('injection_param'), body_format=kwargs.get('body_format'),
                            refresh_config=kwargs.get('refresh_config'),
                            response_regex=kwargs.get('response_regex'),
                            eval_config=kwargs.get('eval_config'),
                            level=kwargs.get('level', 1),
                            risk=kwargs.get('risk', 1))
    asyncio.run(scanner.run())
