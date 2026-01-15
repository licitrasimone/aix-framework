"""AIX Exfil Module - Data exfiltration channel testing"""
import asyncio
import re
from typing import Optional, List, Dict, TYPE_CHECKING
from rich.console import Console
from aix.core.reporter import Severity, Finding
from aix.core.scanner import BaseScanner
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

# Default webhook for testing (user should provide their own)
DEFAULT_WEBHOOK = "https://example.com/exfil"

class ExfilScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 webhook: Optional[str] = None, parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "EXFIL"
        self.console_color = "cyan"
        self.webhook = webhook or DEFAULT_WEBHOOK
        self.browser = kwargs.get('browser') # Passed via kwargs to super
        self.default_payloads = self.load_payloads('exfil.json')

    def _check_exfil_indicators(self, response: str, indicators: List[str]) -> tuple:
        """Check if response contains exfiltration indicators"""
        response_lower = response.lower()
        matched = []
        for ind in indicators:
            if ind.lower() in response_lower:
                matched.append(ind)
        return len(matched) >= 2, matched  # Require at least 2 indicators

    def _extract_urls(self, response: str) -> List[str]:
        """Extract URLs from response"""
        url_pattern = r'https?://[^\s<>"\')\]]+|data:[^\s<>"\')\]]+'
        return re.findall(url_pattern, response, re.IGNORECASE)

    async def run(self, webhook: str = None, payloads: List[Dict] = None):
        if webhook: self.webhook = webhook
        if payloads is None: payloads = self.default_payloads
        
        self._print('info', f'Testing {len(payloads)} exfiltration vectors with webhook: {self.webhook}')

        connector = self._create_connector()
        await connector.connect()

        try:
            for p in payloads:
                self.stats['total'] += 1

                # Replace webhook placeholder
                payload = p['payload'].replace('{webhook}', self.webhook)

                try:
                    resp = await connector.send(payload)

                    # Check for indicators
                    is_vulnerable, matched = self._check_exfil_indicators(resp, p['indicators'])

                    # Also check if our webhook URL appears in response
                    urls_in_response = self._extract_urls(resp)
                    has_external_url = any(self.webhook in url or 'http' in url for url in urls_in_response)

                    if is_vulnerable or has_external_url:
                        self.stats['success'] += 1
                        self._print('success', '', p['name'])
                        self._print('detail', p['description'])

                        if urls_in_response:
                            self._print('detail', f'URLs found: {urls_in_response[:2]}')

                        finding = Finding(
                            title=f"Exfiltration - {p['name']}",
                            severity=p['severity'],
                            technique=p['name'],
                            payload=payload[:200],
                            response=resp[:5000],
                            target=self.target
                        )
                        self.findings.append(finding)

                        self.db.add_result(
                            self.target, 'exfil', p['name'],
                            'success', payload[:200],
                            resp[:5000], p['severity'].value
                        )
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', p['name'])

                except Exception as e:
                    self.stats['blocked'] += 1
                    if self.verbose:
                        self._print('blocked', str(e), p['name'])

                await asyncio.sleep(0.3)

        finally:
            await connector.close()

        # Print summary
        if self.stats['success'] > 0:
            self._print('warning', f"Data exfiltration POSSIBLE via {self.stats['success']} channels!")
        else:
            self._print('info', 'No obvious exfiltration channels found')

        self._print('info', f"{self.stats['success']} vulnerable, {self.stats['blocked']} blocked")

        return self.findings


def run(target: str = None, api_key: str = None, profile: str = None, webhook: str = None,
        browser: bool = False, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return
    
    scanner = ExfilScanner(target, api_key=api_key, webhook=webhook, browser=browser, verbose=verbose,
                           parsed_request=parsed_request, proxy=kwargs.get('proxy'), cookies=kwargs.get('cookies'),
                           headers=kwargs.get('headers'),
                           injection_param=kwargs.get('injection_param'),
                           body_format=kwargs.get('body_format'),
                           refresh_config=kwargs.get('refresh_config'))
    asyncio.run(scanner.run())
