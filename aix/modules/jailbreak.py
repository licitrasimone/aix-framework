"""AIX Jailbreak Module - Bypass AI restrictions"""
import asyncio
from typing import Optional, List, Dict, TYPE_CHECKING
from rich.console import Console
from aix.core.reporter import Severity, Finding
from aix.core.scanner import BaseScanner
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

class JailbreakScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "JAILBRK"
        self.console_color = "cyan"
        self.test_harmful = kwargs.get('test_harmful', False)
        self.default_jailbreaks = self.load_payloads('jailbreak.json')

    async def run(self, jailbreaks: List[Dict] = None):
        if jailbreaks is None: jailbreaks = self.default_jailbreaks
        self._print('info', f'Testing {len(jailbreaks)} jailbreak techniques...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for j in jailbreaks:
                self.stats['total'] += 1
                try:
                    resp = await connector.send(j['payload'])
                    if await self.check_success(resp, j['indicators'], j['payload'], j['name']):
                        self.stats['success'] += 1
                        self._print('success', '', j['name'])
                        self.findings.append(Finding(title=f"Jailbreak - {j['name']}", severity=j['severity'],
                            technique=j['name'], payload=j['payload'][:200], response=resp[:5000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'jailbreak', j['name'], 'success', j['payload'][:200], resp[:5000], j['severity'].value, reason=self.last_eval_reason)
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', j['name'])
                except Exception as e:
                    self.stats['blocked'] += 1
                    if self.verbose:
                        console.print(f"[red]Error in {j['name']}: {e}[/red]")
                await asyncio.sleep(0.5)
        finally:
            await connector.close()

        self._print('info', f"{self.stats['success']} successful, {self.stats['blocked']} blocked")
        return self.findings

def run(target: str = None, api_key: str = None, profile: str = None, browser: bool = False,
        evasion: str = 'light', test_harmful: bool = False, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, cookies: Optional[Dict] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return
    scanner = JailbreakScanner(
        target, api_key=api_key, browser=browser,
        test_harmful=test_harmful, verbose=verbose,
        parsed_request=parsed_request, proxy=kwargs.get('proxy'), cookies=cookies,
        headers=kwargs.get('headers'),
        injection_param=kwargs.get('injection_param'),
        body_format=kwargs.get('body_format'),
        refresh_config=kwargs.get('refresh_config'),
        response_regex=kwargs.get('response_regex'),
        eval_config=kwargs.get('eval_config')
    )
    asyncio.run(scanner.run())
