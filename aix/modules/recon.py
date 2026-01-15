"""AIX Recon Module - Reconnaissance and fingerprinting"""
import asyncio
import re
import json
import os
from typing import Optional, Dict, List, Any, TYPE_CHECKING
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from aix.core.scanner import BaseScanner
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

class ReconScanner(BaseScanner):
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, timeout: int = 30, browser: bool = False, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, timeout=timeout, browser=browser, **kwargs)
        self.module_name = "RECON"
        self.console_color = "cyan"
        
        # Load payloads via loading mechanism (but recon has special structure?)
        # Base scanner load_payloads handles severity format. Recon payloads might differ?
        # Original: self.payloads = json.load(f). No severity reconstruction logic in original? 
        # Wait, original load logic:
        # try: with open... json.load(f) ... except: ... payloads = []
        # No severity reconstruction loop seen in original __init__ logic for recon.json.
        # But wait, lines 37-43 show just json.load.
        # So I can use BaseScanner.load_payloads but it adds severity reconstruction which is harmless if severity key is missing or string.
        # It returns list of dicts.
        self.payloads = self.load_payloads('recon.json')

        # Load config from JSON
        config_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'recon_config.json')
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            console.print(f"[yellow][!] Could not load config from {config_path}: {e}[/yellow]")
            self.config = {
                "model_signatures": {}, "negative_signatures": {}, 
                "version_patterns": {}, "waf_signatures": {}
            }

        self.results = {
            'target': target,
            'model': None,
            'version': None,
            'model_confidence': 0,
            'waf_detected': None,
            'rate_limit': None,
            'auth_type': None,
            'tech_stack': [],
            'supported_params': [],
            'capabilities': [],
            'filters_detected': [],
            'response_times': [],
            'errors': [],
        }

    def _print(self, status: str, msg: str, tech: str = ''):
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        name = "RECON"
        if status == 'info':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [cyan][*][/cyan] {msg}")
        elif status == 'success':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [green][+][/green] {msg}") # Different format than base
        elif status == 'warning':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'error':
            console.print(f"[cyan]RECON[/cyan]   {t:30} [red][-][/red] {msg}")
        # Note: BaseScanner has generic _print but Recon likes its own format slightly (no 'tech' usually in msg for success).

    def _detect_model(self, response: str) -> tuple:
        """Detect AI model using weighted scoring"""
        response_lower = response.lower()
        model_scores = {}

        for model, patterns in self.config.get('model_signatures', {}).items():
            score = 0
            # Add score for positive matches
            for pattern, weight in patterns:
                if pattern in response_lower:
                    score += weight
            
            # Subtract score for negative matches (exclusions)
            if model in self.config.get('negative_signatures', {}):
                for neg_pattern in self.config['negative_signatures'][model]:
                    if neg_pattern in response_lower:
                        score -= 5  # Reduced penalty for conflicting identity
            
            if score > 0:
                model_scores[model] = score

        if not model_scores:
            return None, 0

        best_model = max(model_scores, key=model_scores.get)
        raw_score = model_scores[best_model]
        
        # Calculate confidence: 20 points = 100% confidence
        confidence = min(raw_score * 5, 100)
        
        return best_model, confidence

    def _detect_version(self, model: str, response: str) -> Optional[str]:
        """Extract specific version string from response"""
        version_patterns = self.config.get('version_patterns', {})
        if not model or model not in version_patterns:
            return None
            
        response_lower = response.lower()
        for pattern in version_patterns[model]:
            match = re.search(pattern, response_lower)
            if match:
                return match.group(1)
        return None

    def _detect_waf(self, response: str, headers: Dict = None) -> Optional[str]:
        """Detect WAF from response"""
        response_lower = response.lower()
        headers_str = str(headers).lower() if headers else ""

        for waf, patterns in self.config.get('waf_signatures', {}).items():
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

    async def _probe_rate_limit(self, connector) -> tuple:
        """Probe for rate limiting"""
        count = 0
        limit_hit = False
        
        # Try burst of 5 fast requests
        for i in range(5):
            try:
                await connector.send("ping")
                count += 1
            except Exception as e:
                if '429' in str(e) or 'rate' in str(e).lower():
                    limit_hit = True
                    break
        
        return count, limit_hit

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

        connector = self._create_connector()

        try:
            await connector.connect()

            # Run probing payloads
            self._print('info', f'Running {len(self.payloads)} probe tests...')

            responses = []
            for probe in self.payloads:
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
                    if self.verbose:
                        console.print(f"[red]Error probing {probe['name']}: {e}[/red]")
                    waf = self._detect_waf(str(e))
                    if waf:
                        self.results['waf_detected'] = waf

                await asyncio.sleep(0.3)

            # Analyze responses for model detection
            all_responses = " ".join(r['response'] for r in responses if r.get('response'))
            model, confidence = self._detect_model(all_responses)
            version = self._detect_version(model, all_responses)
            
            self.results['model'] = model
            self.results['version'] = version
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

            # Rate Limit Probing
            self._print('info', 'Probing rate limits...')
            req_count, hit_limit = await self._probe_rate_limit(connector)
            if hit_limit:
                self.results['rate_limit'] = f"Detected (blocked after {req_count} reqs)"
                self._print('warning', f"Rate limit hit after {req_count} requests")
            else:
                 self.results['rate_limit'] = "Not detected (burst allowed)"

            # Save to database
            self.db.add_result(
                self.target, 'recon', 'fingerprint',
                'success' if model else 'partial',
                json.dumps({'probes': len(self.payloads)}),
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
        table.add_row("Version", self.results['version'] or "Unknown")
        table.add_row("Confidence", f"{self.results['model_confidence']}%")
        table.add_row("Auth Type", self.results['auth_type'] or "Unknown")
        table.add_row("WAF", self.results['waf_detected'] or "None detected")
        table.add_row("Rate Limit", self.results['rate_limit'] or "Unknown")
        table.add_row("Capabilities", ", ".join(self.results['capabilities']) or "Standard")

        if self.results['response_times']:
            avg = sum(self.results['response_times']) / len(self.results['response_times'])
            table.add_row("Avg Response", f"{avg:.2f}s")
            
        if self.results['tech_stack']:
             table.add_row("Tech Stack", ", ".join(self.results['tech_stack']))

        console.print(table)


def run(target: str = None, browser: bool = False, output: Optional[str] = None,
        timeout: int = 30, verbose: bool = False,
        parsed_request: Optional['ParsedRequest'] = None, cookies: Optional[Dict] = None, **kwargs) -> None:
    if not target:
        console.print("[red][-][/red] No target specified")
        return

    scanner = ReconScanner(
        target,
        api_key=kwargs.get('api_key'),
        verbose=verbose,
        parsed_request=parsed_request,
        timeout=timeout,
        browser=browser,
        proxy=kwargs.get('proxy'),
        cookies=cookies,
        headers=kwargs.get('headers'),
        body_format=kwargs.get('body_format'),
        injection_param=kwargs.get('injection_param'),
        refresh_config=kwargs.get('refresh_config')
    )
    results = asyncio.run(scanner.run())

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"[green][+][/green] Results saved to {output}")
