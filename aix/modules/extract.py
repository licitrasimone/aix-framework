"""AIX Extract Module - System prompt extraction"""
import asyncio
from typing import Optional, List, Dict, TYPE_CHECKING
from rich.console import Console
from aix.core.reporter import Severity, Finding
from aix.core.scanner import BaseScanner
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

class ExtractScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, browser: bool = False, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "EXTRACT"
        self.console_color = "cyan"
        self.browser = browser # Explicit arg handling if needed, though kwargs handles it too
        self.default_extractions = self.load_payloads('extract.json')

    async def run(self, extractions: List[Dict] = None):
        if extractions is None: extractions = self.default_extractions
        self._print('info', f'Testing {len(extractions)} extraction techniques...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for e in extractions:
                self.stats['total'] += 1
                try:
                    resp = await connector.send(e['payload'])
                    if await self.check_success(resp, e['indicators'], e['payload'], e['name']):
                        self.stats['success'] += 1
                        self._print('success', e['payload'], e['name'])
                        self.findings.append(Finding(title=f"Extraction - {e['name']}", severity=e['severity'],
                            technique=e['name'], payload=e['payload'], response=resp[:5000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'extract', e['name'], 'success', e['payload'], resp[:5000], e['severity'].value, reason=self.last_eval_reason)
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', e['name'])
                except: self.stats['blocked'] += 1
                await asyncio.sleep(0.3)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings


def run(target: str = None, api_key: str = None, profile: str = None,
        browser: bool = False, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, cookies: Optional[Dict] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return

    scanner = ExtractScanner(target, api_key=api_key, browser=browser, verbose=verbose,
                             parsed_request=parsed_request, proxy=kwargs.get('proxy'), cookies=cookies,
                             headers=kwargs.get('headers'),
                             injection_param=kwargs.get('injection_param'),
                             body_format=kwargs.get('body_format'),
                             refresh_config=kwargs.get('refresh_config'),
                             response_regex=kwargs.get('response_regex'),
                             eval_config=kwargs.get('eval_config'))
    asyncio.run(scanner.run())
