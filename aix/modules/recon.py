"""AIX Recon Module - Reconnaissance and fingerprinting"""
import asyncio
import json
import os
import re
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError
from aix.modules.fingerprint import FingerprintScanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class ReconScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
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
            with open(config_path) as f:
                self.config = json.load(f)
        except Exception as e:
            self.console.print(f"[yellow][!] Could not load config from {config_path}: {e}[/yellow]")
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
            'discovered_endpoints': []
        }
        
        # Load discovery paths
        try:
            paths_file = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'discovery_paths.json')
            with open(paths_file) as f:
                self.discovery_paths = json.load(f)
        except Exception:
            self.discovery_paths = ["/v1/chat/completions", "/api/chat", "/api/generate"]


    def _print(self, status: str, msg: str, tech: str = '', response: str = None):
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        name = self.module_name[:7].upper()
        if status == 'info':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [cyan][*][/cyan] {msg}")
        elif status == 'success':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {msg}") # Different format than base
            if self.show_response and response:
                clean_response = response[:500].replace('[', r'\[')
                self.console.print(f"    [dim]Response: {clean_response}[/dim]")
        elif status == 'warning':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'error':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][-][/red] {msg}")
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

    def _detect_version(self, model: str, response: str) -> str | None:
        """Extract specific version string from response"""
        version_patterns = self.config.get('version_patterns', {})
        if not model:
            return None

        # Find matching pattern key
        # 1. Try exact match (e.g., "gpt-4")
        # 2. Try prefix match (e.g., "llama-3" -> "llama")
        target_patterns = []
        if model in version_patterns:
            target_patterns = version_patterns[model]
        else:
            # Fallback: check if any version_pattern key is a prefix of the model
            # e.g. key="llama" matches model="llama-3"
            for key in version_patterns:
                if model.startswith(key) or key in model:
                    target_patterns = version_patterns[key]
                    break
        
        if not target_patterns:
            return None

        response_lower = response.lower()
        for pattern in target_patterns:
            match = re.search(pattern, response_lower)
            if match:
                return match.group(1)
        return None

    def _detect_waf(self, response: str, headers: dict = None) -> str | None:
        """Detect WAF from response"""
        response_lower = response.lower()
        headers_str = str(headers).lower() if headers else ""

        for waf, patterns in self.config.get('waf_signatures', {}).items():
            if any(p in response_lower or p in headers_str for p in patterns):
                return waf
        return None

    def _detect_auth_type(self) -> str:
        """Detect authentication type from request"""
        auth_types = []
        
        # Check Parsed Request headers (most accurate)
        if self.parsed_request:
            headers = {k.lower(): v for k, v in self.parsed_request.headers.items()}
            
            if 'authorization' in headers:
                val = headers['authorization']
                if val.lower().startswith('bearer'):
                    auth_types.append("Bearer Token")
                elif val.lower().startswith('basic'):
                    auth_types.append("Basic Auth")
                else:
                    auth_types.append("Custom Authorization")
            
            # Check for API Key headers
            api_keys = [k for k in headers.keys() if 'api-key' in k or 'x-api-key' in k or 'apikey' in k]
            if api_keys:
                auth_types.append(f"Header API Key ({api_keys[0]})")
                
            # Check for Session Cookies
            if 'cookie' in headers:
                auth_types.append("Session Cookie")
                
        # Check CLI args
        elif self.api_key:
            auth_types.append("Bearer Token (CLI)")
        
        # Check if auth passed via kwargs (cookies/headers)
        if hasattr(self, 'cookies') and self.cookies:
            auth_types.append("Cookies (CLI)")
            
        if not auth_types:
            return "None / Unknown"
            
        return ", ".join(list(set(auth_types)))

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

    async def _discover_endpoint(self, connector) -> str | None:
        """Attempt to discover the correct chat endpoint if the base URL fails"""
        self._print('info', 'Target appears to be a base URL/frontend. Scanning for API endpoints...')
        
        found_endpoint = None
        
        # We'll use a semaphore to limit concurrent checks
        sem = asyncio.Semaphore(10)
        
        async def check_path(base_url, path):
            # Ensure proper joining of base and path
            if base_url.endswith('/'): base_url = base_url[:-1]
            if not path.startswith('/'): path = '/' + path
            full_url = base_url + path
            
            async with sem:
                try:
                    # Send a distinct probe that might trigger "Method Not Allowed" or "Bad Request"
                    # Sending an empty POST is often a good way to find an API
                    # But the connector.send() method is designed for the target URL. 
                    # We need to temporarily use the connector or create raw requests?
                    # Since connector is tied to self.target, we might need a low-level fetch or 
                    # temporarily update connector target if it supports it.
                    # Looking at BaseScanner, connector usually takes url in send() or uses initialized url.
                    # Most connectors (AiohttpConnector) use the initialized session but url is passed in send()??
                    # Let's check BaseScanner/Connector implementation logic if needed. 
                    # Assuming we can request relative paths or absolute URLs.
                    
                    # NOTE: A simple way is to use the existing connector if it allows overriding URL
                    # or just use a raw request if available. 
                    # Since I can't see connector.py, I will assume I can update the target or pass a full URL.
                    # If connector.send takes a payload, it posts TO the target.
                    # We might need a raw "check_url" method. 
                    # For now, I'll attempt to use internal _session of AiohttpConnector if possible, 
                    # OR (safer) instantiate a new connector for the probe? No, that's heavy.
                    
                    # Let's hope the connector allows changing URL or we can hack it. 
                    # Actually, we can just fetch the URL using standard aiohttp if we import it, 
                    # but we want to use the same proxy/headers context.
                    
                    # Heuristic: Check HTTP status
                    # We want 405 (Method Not Allowed), 400 (Bad Request - missing params), or 200 (OK)
                    # We want to avoid 404.
                    
                    # To do this cleanly, let's assume we can try to re-use the connector logic.
                    # If not, I'll use a simple aiohttp request here since we are in `recon`.
                    pass
                except:
                    pass
        
        # Simplification: We will try to update the connector's target or create a quick probe.
        # Since I can't easily see connector.py, I'll assume we can use `connector.session.request` 
        # if it's an AiohttpConnector. 
        
        # Let's just implement a robust probe using the connector's internal session if available
        # or fall back to known behavior.
        
        # ACTUALLY, usually scanners allow probing other paths. 
        # I'll implement a `_probe_path` in ReconScanner utilizing the connector.
        pass

    async def _probe_path(self, connector, path: str) -> bool:
        """Probe a specific path to see if it's an LLM endpoint"""
        try:
            # Construct full URL
            from urllib.parse import urljoin
            full_url = urljoin(self.target, path)
            
            # Use the existing connector's client
            if hasattr(connector, 'client') and connector.client:
                # We need headers. APIConnector has _build_headers but it's internal.
                # We can try to access it or just use minimal headers. 
                headers = {}
                if hasattr(connector, '_build_headers'):
                     headers = connector._build_headers()
                
                # Try POST with empty JSON
                try:
                    resp = await connector.client.post(full_url, json={}, headers=headers)
                    
                    # 405 = Method Not Allowed (Great! It exists but wants other method)
                    # 400 = Bad Request (Great! It exists but wants body)
                    # 415 = Unsupported Media Type
                    # 422 = Unprocessable Entity
                    # 200 = OK
                    if resp.status_code in [200, 400, 405, 415, 422]:
                        return True
                        
                    # Also check content for "error" related to LLMs
                    text = resp.text.lower()
                    if 'message' in text or 'model' in text or 'instruction' in text or 'missing' in text:
                        return True
                except:
                    pass
            return False
        except:
            return False

    async def _extract_apis_from_js(self, connector, html: str) -> list[str]:
        """Extract potential API URLs from JavaScript files"""
        self._print('info', 'Analyzing JavaScript for API endpoints...')
        found_urls = set()
        
        # 1. Find script sources
        # Simple regex for <script src="...">
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
        
        # 2. Extract full URLs from inline HTML/Scripts
        # Pattern for http/https URLs
        url_pattern = r'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=-]*)?'
        matches = re.findall(url_pattern, html)
        found_urls.update(matches)
        
        # Filter for external scripts to fetch
        scripts_to_fetch = []
        for src in script_srcs:
            # Ignore common 3rd party libs to save time
            lower_src = src.lower()
            if any(x in lower_src for x in ['jquery', 'analytics', 'gtm', 'ads', 'doubleclick', 'facebook', 'twitter', 'fontawesome']):
                continue
                
            # Handle relative URLs
            from urllib.parse import urljoin
            full_src = urljoin(self.target, src)
            scripts_to_fetch.append(full_src)
            
        # 3. Fetch and scan JS files
        async def fetch_and_scan(url):
            try:
                if hasattr(connector, 'client') and connector.client:
                    r = await connector.client.get(url, timeout=5)
                    if r.status_code == 200:
                        content = r.text
                        # Find URLs in JS
                        js_matches = re.findall(url_pattern, content)
                        return js_matches
            except:
                pass
            return []

        if scripts_to_fetch:
            self._print('info', f'Scanning {len(scripts_to_fetch)} JS files...')
            tasks = [fetch_and_scan(url) for url in scripts_to_fetch[:10]] # Limit to 10 scripts
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    found_urls.update(r)

        # 4. Filter for relevant API-like URLs
        api_candidates = []
        keywords = ['api', 'chat', 'v1', 'openai', 'azure', 'anthropic', 'cohere', 'completions', 'generate', 'invoke', 'graphql', 'model']
        
        for url in found_urls:
            lower_url = url.lower()
            # Must contain at least one AI/API keyword
            if any(k in lower_url for k in keywords):
                # Exclude the target itself if it's just the base URL
                if url.rstrip('/') == self.target.rstrip('/'):
                    continue
                # Exclude common noisy URLs
                if any(x in lower_url for x in ['schema.org', 'w3.org', 'github.com/facebook', 'twitter.com']):
                    continue
                    
                api_candidates.append(url)
                
        return list(set(api_candidates))

    async def _run_discovery(self, connector):

        """Run the full discovery process"""
        found = []
        
        async def worker(path):
            if await self._probe_path(connector, path):
                return path
            return None
            
        # Phase 1: Probe common paths on current domain
        self._print('info', 'Phase 1: Probing common API paths...')
        tasks = [worker(p) for p in self.discovery_paths]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            if r:
                found.append(r)
        
        # Phase 2: Static Analysis (JS Extraction)
        # We need the HTML content first.
        try:
            if hasattr(connector, 'client') and connector.client:
                resp = await connector.client.get(self.target)
                if resp.status_code == 200:
                    js_apis = await self._extract_apis_from_js(connector, resp.text)
                    if js_apis:
                        self._print('success', f"Found {len(js_apis)} potential APIs in JS: {', '.join(js_apis[:3])}...")
                        found.extend(js_apis)
        except Exception as e:
            self._print('warning', f"JS Analysis failed: {e}")

        return list(set(found))


    async def run(self) -> dict[str, Any]:
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

            # --- STEP 0: Endpoint Discovery ---
            # If the base URL looks like a frontend (HTML) or gives 404, try to find the API
            initial_check = False
            try:
                # Quick check of the base URL
                # We interpret "success" or "valid" response? 
                # Actually, let's just trigger discovery if the user provided a root URL 
                # and explicitly asked for it OR if we suspect it.
                # For now: Auto-trigger if root path '/'
                
                should_discover = False
                if parsed_url.path in ['', '/']:
                    should_discover = True
                
                # Or verify response content type?
                # Let's run discovery concurrently with probes? No, better before.
                
                if should_discover:
                    self._print('info', "Root URL detected. Attempting to discover API endpoints...")
                    found_paths = await self._run_discovery(connector)
                    if found_paths:
                        best_path = found_paths[0] # Take first for now
                        self._print('success', f"Discovered API endpoint: {best_path}")
                        
                        # Update target to point to the API
                        from urllib.parse import urljoin
                        # If best_path is absolute, urljoin handles it correctly (ignores base)
                        self.target = urljoin(self.target, best_path)
                        self._print('info', f"Switched target to {self.target}")
                        self.results['discovered_endpoints'] = found_paths

                        # Re-initialize connector with new target so subsequent probes use the correct URL
                        await connector.close()
                        connector = self._create_connector()
                        await connector.connect()
                    else:
                        self._print('warning', "No specific API endpoints found. Continuing with base URL.")
            
            except Exception as e:
                self._print('warning', f"Discovery failed: {e}")

            # --- END DISCOVERY ---

            # Run probing payloads
            self._print('info', f'Running {len(self.payloads)} probe tests...')

            responses = []
            for probe in track(self.payloads, description="[bold white]🔍 Mapping Surface...  [/]", console=self.console):
                try:
                    import time
                    start = time.time()
                    resp = await connector.send(probe['payload'])
                    elapsed = time.time() - start
                    self.results['response_times'].append(elapsed)


                    # Validate if probe was successful (answered vs refused)
                    # We pass empty indicators because recon.json doesn't have them, relying on LLM or simple pass
                    is_valid = await self.check_success(resp, [], probe['payload'], 'recon')

                    if is_valid:
                        self.findings.append(Finding(title=f"Recon - {probe['name']}", severity=probe.get('severity', Severity.INFO),
                                technique=probe['name'], payload=probe['payload'], response=resp[:2000], target=self.target, reason=self.last_eval_reason))
                        self.db.add_result(self.target, 'recon', probe['name'], 'success', probe['payload'], resp[:2000], probe.get('severity', Severity.INFO).value, reason=self.last_eval_reason)
                        
                        if self.show_response:
                            self._print('success', f"Probe {probe['name']}", response=resp)

                    responses.append({
                        'probe': probe['name'],
                        'response': resp,
                        'time': elapsed,
                        'valid': is_valid
                    })

                    if self.verbose:
                        status_icon = "[green]✓[/green]" if is_valid else "[red]✗[/red]"
                        self._print('info', f'Probe {probe["name"]}: {elapsed:.2f}s {status_icon}')

                except Exception as e:
                    self.results['errors'].append(str(e))
                    
                    # Clean error printing
                    error_str = str(e)
                    if "Authentication Failed" in error_str:
                         # Only print auth failure once to avoid spam
                         if not any("Authentication Failed" in err for err in self.results['errors'][:-1]):
                             self._print('error', f"Authentication failed: Target requires valid credentials (401/403)")
                             self._update_error_state(error_str)
                    elif "403" in error_str:
                         self._print('error', f"Target returned 403 Forbidden ({probe['name']})")
                         self._update_error_state(error_str)
                    elif "500" in error_str:
                         self._print('error', f"Target returned 500 Server Error ({probe['name']})")
                         self._update_error_state(error_str)
                    elif self.verbose:
                        import traceback
                        self.console.print(f"[red]Error probing {probe['name']}: {e}[/red]")
                        self.console.print(traceback.format_exc())
                        self._update_error_state(None)
                    else:
                        # Print generic error concisely if not Auth (which is handled above)
                        if "Authentication Failed" not in error_str and "Rate Limit" not in error_str:
                             self._print('error', f"Probe {probe['name']} failed: {error_str.split(':')[0]}")
                             self._update_error_state(None)

                    waf = self._detect_waf(str(e))
                    if waf:
                        self.results['waf_detected'] = waf

                except CircuitBreakerError:
                    break # Stop scan

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

        # Run probabilistic fingerprinting if confidence is low
        if self.results['model_confidence'] < 80:
            self.console.print()
            self._print('info', f"Standard confidence <80%. Initiating Advanced Fingerprinting...")
            await self._run_advanced_fingerprint()
            
            # Re-print summary if we updated something? 
            # Ideally we print summary AFTER everything.
            # Moving _print_summary call to end of run() is already correct.

        # Print summary
        self._print_summary()
        return self.results

    def _print_summary(self):
        """Print reconnaissance summary"""
        self.console.print()
        from rich.box import ROUNDED
        from rich.panel import Panel
        from rich.table import Table
        
        # Main Results Table
        table = Table(title="🎯 Reconnaissance Report", box=ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Property", style="bold white", width=20)
        table.add_column("Value", style="green")

        # Helper for color-coding confidence
        conf_style = "green" if self.results['model_confidence'] > 70 else "yellow" if self.results['model_confidence'] > 30 else "red"
        
        # Add basic info
        table.add_row("Target URL", f"[link={self.target}]{self.target}[/link]")
        table.add_row("Model Detected", f"[bold {conf_style}]{self.results['model'] or 'Unknown'}[/]")
        table.add_row("Version", self.results['version'] or "Unknown")
        table.add_row("Confidence Score", f"[{conf_style}]{self.results['model_confidence']}%[/]")
        table.add_row("Authentication", self.results['auth_type'])
        
        # WAF Status
        waf = self.results['waf_detected']
        table.add_row("WAF / Protection", f"[red]{waf}[/]" if waf else "[green]None Detected[/]")
        
        # Capabilities
        caps = self.results['capabilities']
        if caps:
            table.add_row("Agent Capabilities", f"[cyan]{', '.join(caps)}[/]")
        else:
             table.add_row("Agent Capabilities", "[dim]No tools detected[/]")

        # Performance
        if self.results['response_times']:
            avg = sum(self.results['response_times']) / len(self.results['response_times'])
            color = "green" if avg < 1.0 else "yellow" if avg < 3.0 else "red"
            table.add_row("Avg Latency", f"[{color}]{avg:.2f}s[/]")
            
        self.console.print(table)
        
        # Discovered Endpoints Panel
        if self.results.get('discovered_endpoints'):
            eps = "\n".join([f"[green]✓[/] {ep}" for ep in self.results['discovered_endpoints']])
            self.console.print(Panel(eps, title="🔍 Discovered API Endpoints", border_style="cyan"))

    async def _run_advanced_fingerprint(self):
        """Run advanced probability-based fingerprinting"""
        try:
            # Pass cookies explicitly if auth is cookie-based
            # Also pass parsed_request if we are using it (for -r mode) to ensure correct headers/body
            
            # Print start message in standard format
            # accessing 'db' is hard here without loading it, so we just say "Running probes..."
            # or we can ask fp how many Qs it has. 
            # Simplified:
            self._print('info', "Running advanced fingerprint probes...")

            fp = FingerprintScanner(
                self.target,
                api_key=self.api_key,
                proxy=self.proxy,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                parsed_request=self.parsed_request,  # Critical fix for -r request mode
                verbose=self.verbose,
                console=self.console
            )
            
            # Using the same connector session would be ideal but for now we let it manage its own
            winner = await fp.run()
            
            if winner:
                # Update our main results if fingerprinting found a winner
                # Always overwrite because fingerprinting is more granular/accurate
                self.results['model'] = winner
                self.results['model_confidence'] = 90 # High confidence if fingerprint logic matches
                # family is in fp.db... accessing it is messy without method.
                # Simplified update:
                self.results['fingerprint_winner'] = winner

        except Exception as e:
            self.console.print(f"[yellow][!] Advanced fingerprinting failed: {e}[/yellow]")



def run(target: str = None, browser: bool = False, output: str | None = None,
        timeout: int = 30, verbose: bool = False,
        parsed_request: Optional['ParsedRequest'] = None, cookies: dict | None = None, show_response: bool = False, **kwargs) -> None:
    if not target:
        print("[red][-][/red] No target specified")
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
        refresh_config=kwargs.get('refresh_config'),
        response_regex=kwargs.get('response_regex'),
        eval_config=kwargs.get('eval_config'),
        level=kwargs.get('level', 1),
        risk=kwargs.get('risk', 1),
        show_response=show_response,
        evasion=kwargs.get('evasion', 'none')
    )
    results = asyncio.run(scanner.run())

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[green][+][/green] Results saved to {output}")
