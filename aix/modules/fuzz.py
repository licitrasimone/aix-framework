"""AIX Fuzz Module - Fuzzing and edge case testing"""
import asyncio
import random
import string
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

class FuzzScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, iterations: int = 100, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "FUZZ"
        self.console_color = "cyan"
        self.iterations = iterations
        self._init_stats(errors=0, anomalies=0) # We'll map anomalies to success usually, but keeping separate for clarity if needed, or just use success?
        # Code uses 'anomalies'. base has 'success'.
        # Let's map 'anomalies' -> 'success' in this refactor to standardize.
        self.stats['anomalies'] = 0 # Explicitly keeping it for backward compat in logic if needed, or just remove and use success.
        # I'll use success for anomalies.
        
        # Load config
        config_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'fuzz_config.json')
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            console.print(f"[yellow][!] Could not load config from {config_path}: {e}[/yellow]")
            self.config = {"unicode_fuzz": [], "format_strings": []}
            
        # Re-initialize control chars dynamically (not in config)
        self.control_chars = [chr(i) for i in range(32)] + [chr(127)]
        
        self.default_payloads = self.load_payloads('fuzz.json')
        self.baseline_response = None

    def _print(self, status: str, msg: str, tech: str = ''):
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        name = self.module_name[:7].upper()
        
        if status == 'success':
            # Custom message for anomaly
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {tech} [bold green](Anomaly!)[/bold green]")
        elif status == 'progress':
            console.print(f"[dim]Fuzz iteration {msg}[/dim]")
        else:
            super()._print(status, msg, tech)

    def _generate_random_fuzz(self) -> List[Dict]:
        """Generate random fuzz payloads"""
        payloads = []

        # Random unicode strings
        for i in range(10):
            chars = [random.choice(self.config['unicode_fuzz']) for _ in range(random.randint(1, 10))]
            payloads.append({
                'name': f'random_unicode_{i}',
                'payload': 'Test ' + ''.join(chars) + ' message',
                'category': 'random_unicode',
                'severity': Severity.LOW
            })

        # Random control characters
        for i in range(5):
            chars = [random.choice(self.control_chars) for _ in range(random.randint(1, 5))]
            payloads.append({
                'name': f'random_control_{i}',
                'payload': 'Test ' + ''.join(chars) + ' message',
                'category': 'random_control',
                'severity': Severity.MEDIUM
            })

        # Random very long strings
        for i in range(3):
            length = random.randint(5000, 20000)
            char = random.choice(string.ascii_letters)
            payloads.append({
                'name': f'random_long_{i}',
                'payload': char * length,
                'category': 'random_long',
                'severity': Severity.MEDIUM
            })

        return payloads

    def _is_anomaly(self, response: str, payload: Dict) -> tuple:
        """Detect anomalies in response"""
        anomalies = []

        # Check for error indicators
        error_indicators = ['error', 'exception', 'traceback', 'stack trace', 'undefined', 'null pointer']
        for indicator in error_indicators:
            if indicator.lower() in response.lower():
                anomalies.append(f'Error indicator: {indicator}')

        # Check for information disclosure
        disclosure_indicators = ['internal', 'debug', 'version:', 'server:', 'path:', 'file:']
        for indicator in disclosure_indicators:
            if indicator.lower() in response.lower() and indicator.lower() not in payload['payload'].lower():
                anomalies.append(f'Info disclosure: {indicator}')

        # Check for reflected payload (potential XSS/injection)
        if payload['category'] in ['format', 'injection', 'xml']:
            dangerous_reflects = ['<script', '${', '#{', '{{', '%n', '%x']
            for reflect in dangerous_reflects:
                if reflect in payload['payload'] and reflect in response:
                    anomalies.append(f'Payload reflected: {reflect}')

        # Check for unusual response patterns
        if len(response) > 50000:
            anomalies.append(f'Unusually long response: {len(response)} chars')

        if response.count('\x00') > 0:
            anomalies.append('Null bytes in response')

        return len(anomalies) > 0, anomalies

    async def run(self, payloads: List[Dict] = None):
        if payloads is None: payloads = self.default_payloads.copy()

        # Add random fuzzing if iterations are high
        if self.iterations > len(payloads):
            random_payloads = self._generate_random_fuzz()
            payloads.extend(random_payloads)

        # Limit to iterations count
        payloads = payloads[:self.iterations]

        self._print('info', f'Running {len(payloads)} fuzz tests...')

        connector = self._create_connector()
        await connector.connect()

        try:
            # Get baseline response
            try:
                self.baseline_response = await connector.send("Hello, how are you?")
            except:
                self.baseline_response = ""

            for i, p in enumerate(payloads):
                self.stats['total'] += 1

                # Progress indicator
                if self.verbose and i > 0 and i % 10 == 0:
                    self._print('progress', f'{i}/{len(payloads)}')

                try:
                    resp = await connector.send(p['payload'])

                    # Check for anomalies
                    is_anomaly, anomaly_details = self._is_anomaly(resp, p)

                    if is_anomaly:
                        self.stats['success'] += 1 # Anomalies -> Success
                        self._print('success', '', p['name'])
                        for detail in anomaly_details[:3]:
                            self._print('detail', detail)

                        finding = Finding(
                            title=f"Fuzz Anomaly - {p['name']}",
                            severity=p['severity'],
                            technique=p['name'],
                            payload=p['payload'][:200] if len(p['payload']) < 500 else f"{p['payload'][:100]}... ({len(p['payload'])} chars)",
                            response=resp[:5000],
                            target=self.target
                        )
                        self.findings.append(finding)

                        self.db.add_result(
                            self.target, 'fuzz', p['name'],
                            'anomaly', p['payload'][:200],
                            resp[:5000], p['severity'].value
                        )
                    else:
                        self.stats['blocked'] += 1

                except Exception as e:
                    self.stats['errors'] += 1
                    error_str = str(e)

                    # Some errors might indicate vulnerabilities
                    if 'timeout' in error_str.lower() or '500' in error_str:
                        self._print('warning', f'{p["name"]}: Server error/timeout')

                        finding = Finding(
                            title=f"Fuzz Error - {p['name']}",
                            severity=Severity.MEDIUM,
                            technique=p['name'],
                            payload=p['payload'][:200],
                            response=f"Error: {error_str[:200]}",
                            target=self.target
                        )
                        self.findings.append(finding)

                await asyncio.sleep(0.1)

        finally:
            await connector.close()

        # Print summary
        if self.stats['success'] > 0:
            self._print('warning', f"Found {self.stats['success']} anomalies!")
        else:
            self._print('info', 'No anomalies detected')

        self._print('info', f"{self.stats['success']} anomalies, {self.stats['errors']} errors, {self.stats['blocked']} normal")

        return self.findings


def run(target: str = None, api_key: str = None, profile: str = None, browser: bool = False,
        iterations: int = 100, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, cookies: Optional[Dict] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return

    scanner = FuzzScanner(target, api_key=api_key, verbose=verbose,
                          parsed_request=parsed_request, iterations=iterations, 
                          proxy=kwargs.get('proxy'), cookies=cookies, headers=kwargs.get('headers'), injection_param=kwargs.get('injection_param'),
                          body_format=kwargs.get('body_format'), refresh_config=kwargs.get('refresh_config'))
    asyncio.run(scanner.run())

__all__ = ["run"]
