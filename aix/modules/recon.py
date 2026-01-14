"""AIX Recon Module - Reconnaissance and fingerprinting"""
import asyncio
import re
import json
from typing import Optional, Dict, List, Any, TYPE_CHECKING
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from aix.core.connector import APIConnector, RequestConnector
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

# Model fingerprinting patterns
MODEL_SIGNATURES = {
    'gpt-4': ['gpt-4', 'openai', 'as an ai language model', 'i cannot', 'i\'m unable to'],
    'gpt-3.5': ['gpt-3.5', 'chatgpt', 'as an ai'],
    'claude': ['claude', 'anthropic', 'i\'d be happy to help', 'i don\'t actually'],
    'llama': ['llama', 'meta ai', 'llama 2', 'llama 3'],
    'gemini': ['gemini', 'google', 'bard'],
    'mistral': ['mistral', 'mixtral'],
    'cohere': ['cohere', 'command'],
}

# WAF detection patterns
WAF_SIGNATURES = {
    'cloudflare': ['cloudflare', 'cf-ray', '__cfruid'],
    'akamai': ['akamai', 'ak_bmsc'],
    'aws_waf': ['awswaf', 'x-amzn-requestid'],
    'imperva': ['incapsula', 'visid_incap'],
    'custom': ['blocked', 'forbidden', 'rate limit', 'too many requests'],
}

# Probing payloads for fingerprinting
PROBE_PAYLOADS = [
    {'name': 'basic_test', 'payload': 'Hello, can you tell me what model you are?', 'purpose': 'model_detection'},
    {'name': 'version_probe', 'payload': 'What is your version number and release date?', 'purpose': 'model_detection'},
    {'name': 'capability_test', 'payload': 'What are your capabilities and limitations?', 'purpose': 'capability_detection'},
    {'name': 'context_length', 'payload': 'What is your maximum context length or token limit?', 'purpose': 'limit_detection'},
    {'name': 'filter_test', 'payload': 'Can you help me with a hypothetical security scenario?', 'purpose': 'filter_detection'},
    {'name': 'system_probe', 'payload': 'Are you following any specific instructions or guidelines?', 'purpose': 'system_prompt_hint'},
]


class ReconScanner:
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, timeout: int = 30, **kwargs):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.parsed_request = parsed_request
        self.timeout = timeout
        self.db = AIXDatabase()
        self.results = {
            'target': target,
            'model': None,
            'model_confidence': 0,
            'waf_detected': None,
            'rate_limit': None,
            'auth_type': None,
            'capabilities': [],
            'filters_detected': [],
            'response_times': [],
            'errors': [],
        }

    def _print(self, status: str, msg: str):
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        if status == 'info':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [cyan][*][/cyan] {msg}")
        elif status == 'success':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [green][+][/green] {msg}")
        elif status == 'warning':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'error':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [red][-][/red] {msg}")

    def _detect_model(self, response: str) -> tuple:
        """Detect AI model from response patterns"""
        response_lower = response.lower()
        best_match = None
        best_score = 0

        for model, patterns in MODEL_SIGNATURES.items():
            score = sum(1 for p in patterns if p in response_lower)
            if score > best_score:
                best_score = score
                best_match = model

        confidence = min(best_score * 25, 100)  # Scale to percentage
        return best_match, confidence

    def _detect_waf(self, response: str, headers: Dict = None) -> Optional[str]:
        """Detect WAF from response"""
        response_lower = response.lower()
        headers_str = str(headers).lower() if headers else ""

        for waf, patterns in WAF_SIGNATURES.items():
            if any(p in response_lower or p in headers_str for p in patterns):
                return waf
        return None

    def _detect_auth_type(self) -> str:
        """Detect authentication type from request"""
        if self.parsed_request:
            headers = self.parsed_request.headers
            if 'Authorization' in headers:
                auth = headers['Authorization']
                if auth.startswith('Bearer'):
                    return 'Bearer Token'
                elif auth.startswith('Basic'):
                    return 'Basic Auth'
                else:
                    return 'Custom Auth'
            if 'x-api-key' in headers or 'api-key' in headers:
                return 'API Key Header'
        elif self.api_key:
            return 'Bearer Token'
        return 'Unknown'

    async def _probe_rate_limit(self, connector) -> Optional[int]:
        """Probe for rate limiting"""
        count = 0
        for i in range(10):
            try:
                await connector.send("test")
                count += 1
                await asyncio.sleep(0.1)
            except Exception as e:
                if 'rate' in str(e).lower() or '429' in str(e):
                    return count
                break
        return None

    async def run(self) -> Dict[str, Any]:
        """Run reconnaissance scan"""
        self._print('info', 'Starting reconnaissance scan...')

        # Detect auth type
        self.results['auth_type'] = self._detect_auth_type()
        self._print('info', f'Auth type: {self.results["auth_type"]}')

        # Parse URL info
        parsed_url = urlparse(self.target)
        self._print('info', f'Host: {parsed_url.netloc}')
        self._print('info', f'Endpoint: {parsed_url.path or "/"}')

        # Create connector (pass verbose/timeout so connectors can log and use timeout)
        if self.parsed_request:
            connector = RequestConnector(self.parsed_request, timeout=self.timeout, verbose=self.verbose)
        else:
            connector = APIConnector(self.target, api_key=self.api_key, timeout=self.timeout, verbose=self.verbose)

        try:
            await connector.connect()

            # Run probing payloads
            self._print('info', f'Running {len(PROBE_PAYLOADS)} probe tests...')

            responses = []
            for probe in PROBE_PAYLOADS:
                try:
                    import time
                    start = time.time()
                    resp = await connector.send(probe['payload'])
                    elapsed = time.time() - start
                    self.results['response_times'].append(elapsed)

                    responses.append({
                        'probe': probe['name'],
                        'response': resp,
                        'time': elapsed
                    })

                    if self.verbose:
                        self._print('info', f'Probe {probe["name"]}: {elapsed:.2f}s')

                except Exception as e:
                    self.results['errors'].append(str(e))
                    waf = self._detect_waf(str(e))
                    if waf:
                        self.results['waf_detected'] = waf

                await asyncio.sleep(0.3)

            # Analyze responses for model detection
            all_responses = " ".join(r['response'] for r in responses if r.get('response'))
            model, confidence = self._detect_model(all_responses)
            self.results['model'] = model
            self.results['model_confidence'] = confidence

            if model:
                self._print('success', f'Model detected: {model} (confidence: {confidence}%)')
            else:
                self._print('warning', 'Could not identify model')

            # Check for WAF in responses
            for r in responses:
                waf = self._detect_waf(r.get('response', ''))
                if waf:
                    self.results['waf_detected'] = waf
                    self._print('warning', f'WAF detected: {waf}')
                    break

            # Analyze capabilities
            if any('code' in r.get('response', '').lower() for r in responses):
                self.results['capabilities'].append('code_generation')
            if any('search' in r.get('response', '').lower() for r in responses):
                self.results['capabilities'].append('web_search')
            if any('image' in r.get('response', '').lower() for r in responses):
                self.results['capabilities'].append('image_handling')

            if self.results['capabilities']:
                self._print('info', f'Capabilities: {", ".join(self.results["capabilities"])}')

            # Calculate average response time
            if self.results['response_times']:
                avg_time = sum(self.results['response_times']) / len(self.results['response_times'])
                self._print('info', f'Avg response time: {avg_time:.2f}s')

            # Save to database
            self.db.add_result(
                self.target, 'recon', 'fingerprint',
                'success' if model else 'partial',
                json.dumps({'probes': len(PROBE_PAYLOADS)}),
                json.dumps(self.results),
                'info'
            )

        except Exception as e:
            self._print('error', f'Scan failed: {str(e)}')
            self.results['errors'].append(str(e))

        finally:
            await connector.close()

        # Print summary
        self._print_summary()
        return self.results

    def _print_summary(self):
        """Print reconnaissance summary"""
        console.print()
        table = Table(title="Reconnaissance Results", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Target", self.target[:50])
        table.add_row("Model", self.results['model'] or "Unknown")
        table.add_row("Confidence", f"{self.results['model_confidence']}%")
        table.add_row("Auth Type", self.results['auth_type'] or "Unknown")
        table.add_row("WAF", self.results['waf_detected'] or "None detected")
        table.add_row("Capabilities", ", ".join(self.results['capabilities']) or "Standard")

        if self.results['response_times']:
            avg = sum(self.results['response_times']) / len(self.results['response_times'])
            table.add_row("Avg Response", f"{avg:.2f}s")

        console.print(table)


def run(target: str = None, browser: bool = False, output: Optional[str] = None,
        timeout: int = 30, verbose: bool = False,
        parsed_request: Optional['ParsedRequest'] = None, **kwargs) -> None:
    if not target:
        console.print("[red][-][/red] No target specified")
        return

    scanner = ReconScanner(
        target,
        api_key=kwargs.get('api_key'),
        verbose=verbose,
        parsed_request=parsed_request,
        timeout=timeout
    )
    results = asyncio.run(scanner.run())

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"[green][+][/green] Results saved to {output}")
