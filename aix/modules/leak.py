"""AIX Leak Module - Training data and sensitive information leakage"""
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

import os
import json


class LeakScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, browser: bool = False, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "LEAK"
        self.console_color = "red" # Leak usually uses cyan? Code used cyan. BaseScanner default white. I'll use cyan to match others or red/yellow for leaks? Original code used cyan in _print.
        self.console_color = "cyan"
        self.browser = browser
        
        # Load config (PII patterns)
        config_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'leak_config.json')
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            console.print(f"[yellow][!] Could not load config from {config_path}: {e}[/yellow]")
            self.config = {"pii_patterns": {}}
            
        self.default_probes = self.load_payloads('leak.json')

    def _check_pii(self, response: str) -> List[Dict]:
        """Check response for PII patterns"""
        found = []
        for pii_type, pattern in self.config.get('pii_patterns', {}).items():
            matches = re.findall(pattern, response, re.IGNORECASE)
            if matches:
                found.append({
                    'type': pii_type,
                    'count': len(matches),
                    'samples': matches[:3]  # Limit samples for privacy
                })
        return found

    def _check_indicators(self, response: str, indicators: List[str]) -> bool:
        """Check if response contains any indicators"""
        response_lower = response.lower()
        return any(ind.lower() in response_lower for ind in indicators)

    async def run(self, probes: List[Dict] = None):
        if probes is None: probes = self.default_probes

        self._print('info', f'Testing {len(probes)} leak detection probes...')

        connector = self._create_connector()
        await connector.connect()

        try:
            for probe in probes:
                self.stats['total'] += 1
                try:
                    resp = await connector.send(probe['payload'])
                    leak_detected = False
                    leak_details = {}

                    # Check for PII patterns if specified
                    if 'check' in probe:
                        pii_patterns = self.config.get('pii_patterns', {})
                        for pii_type in probe['check']:
                            if pii_type in pii_patterns:
                                matches = re.findall(pii_patterns[pii_type], resp, re.IGNORECASE)
                                if matches:
                                    leak_detected = True
                                    leak_details[pii_type] = len(matches)

                    # Check for indicators if specified
                    if 'indicators' in probe:
                        if self._check_indicators(resp, probe['indicators']):
                            leak_detected = True
                            leak_details['indicators_matched'] = True

                    if leak_detected:
                        self.stats['success'] += 1
                        self._print('success', '', probe['name'])

                        finding = Finding(
                            title=f"Data Leak - {probe['name']}",
                            severity=probe['severity'],
                            technique=probe['name'],
                            payload=probe['payload'],
                            response=resp[:500],
                            target=self.target
                        )
                        self.findings.append(finding)

                        self.db.add_result(
                            self.target, 'leak', probe['name'],
                            'success', probe['payload'],
                            resp[:500], probe['severity'].value
                        )
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', probe['name'])

                except Exception as e:
                    self.stats['blocked'] += 1
                    if self.verbose:
                        self._print('blocked', str(e), probe['name'])

                await asyncio.sleep(0.3)

        finally:
            await connector.close()

        # Print summary
        if self.stats['success'] > 0:
            self._print('warning', f"Found {self.stats['success']} potential data leaks!")
        else:
            self._print('info', 'No obvious data leaks detected')

        self._print('info', f"{self.stats['success']} leaks, {self.stats['blocked']} blocked")

        return self.findings


def run(target: str = None, api_key: str = None, profile: str = None,
        browser: bool = False, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return
    
    scanner = LeakScanner(target, api_key=api_key, browser=browser, verbose=verbose,
                          parsed_request=parsed_request, proxy=kwargs.get('proxy'), cookies=kwargs.get('cookies'),
                          headers=kwargs.get('headers'),
                          injection_param=kwargs.get('injection_param'),
                          body_format=kwargs.get('body_format'))
    asyncio.run(scanner.run())
