"""AIX DoS Module - Denial of Service and resource exhaustion testing"""
import asyncio
import time
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.progress import track

from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest



class DoSScanner(BaseScanner):
    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, safe_mode: bool = True, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "DOS"
        self.console_color = "cyan"
        self.safe_mode = safe_mode
        self.browser = kwargs.get('browser') # Kwargs passed to super, but needed if used explicitly? Not used in run methods explicitly (passed to connector via super logic). Wait, run logic uses _create_connector from base.
        self._init_stats(timeouts=0)
        self.default_payloads = self.load_payloads('dos.json')
        self.baseline_time = None

    def _print(self, status: str, msg: str, tech: str = ''):
        if status == 'timeout':
            t = self.target[:28] + '...' if len(self.target) > 30 else self.target
            name = self.module_name[:7].upper()
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {tech} [yellow](Timeout - potential DoS)[/yellow]")
        else:
            super()._print(status, msg, tech)

    async def _establish_baseline(self, connector) -> float:
        """Establish baseline response time"""
        times = []
        for _ in range(3):
            try:
                start = time.time()
                await connector.send("Hello, how are you?")
                elapsed = time.time() - start
                times.append(elapsed)
                await asyncio.sleep(0.2)
            except Exception:
                pass
        return sum(times) / len(times) if times else 2.0

    async def _test_rate_limit(self, connector, count: int = 20) -> dict:
        """Test rate limiting"""
        self._print('info', f'Testing rate limit ({count} requests)...')
        results = {'success': 0, 'blocked': 0, 'rate_limit_hit': False}

        for i in range(count):
            try:
                await connector.send(f"Test message {i}")
                results['success'] += 1
            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'rate' in error_str or 'limit' in error_str:
                    results['rate_limit_hit'] = True
                    results['blocked'] = count - i
                    self._print('info', f'Rate limit hit after {i} requests')
                    break
                results['blocked'] += 1
            await asyncio.sleep(0.05)  # Minimal delay for burst

        return results

    async def run(self, payloads: list[dict] = None):
        if payloads is None:
            payloads = self.default_payloads

        connector = self._create_connector()
        await connector.connect()
        await self.gather_context(connector)

        # Generate context-aware payloads if requested
        if self.generate_count > 0 and self.ai_engine and self.context:
            generated = await self.generate_payloads()
            if generated:
                payloads = payloads + generated

        self._print('info', f'Testing {len(payloads)} DoS techniques...')
        if self.safe_mode:
            self._print('info', 'Safe mode enabled - limited test intensity')

        try:
            # Establish baseline
            self._print('info', 'Establishing baseline response time...')
            self.baseline_time = await self._establish_baseline(connector)
            self._print('info', f'Baseline: {self.baseline_time:.2f}s')



            for p in track(payloads, description="[bold red]💥 Overloading Synapses[/]", console=self.console, disable=not self.show_progress):
                self.stats['total'] += 1

                # Handle rate limit testing separately
                if p.get('burst'):
                    if self.safe_mode:
                        count = min(p.get('count', 10), 10)
                    else:
                        count = p.get('count', 20)
                    rate_results = await self._test_rate_limit(connector, count)

                    if rate_results['rate_limit_hit']:
                        self._print('info', 'Rate limiting is active')
                    else:
                        self._print('warning', 'No rate limiting detected!')
                        self.stats['success'] += 1 # Changed 'vulnerable' to 'success'

                        finding = Finding(
                            title="DoS - No Rate Limiting",
                            severity=Severity.HIGH,
                            technique='rate_limit',
                            payload=f"Burst test: {count} requests",
                            response=f"All {rate_results['success']} requests succeeded",
                            target=self.target,
                            owasp=p.get('owasp', [])
                        )
                        self.findings.append(finding)
                    continue

                # Standard payload tests
                try:
                    # Truncate very long payloads in safe mode
                    payload = p['payload']
                    if self.safe_mode and len(payload) > 1000:
                        payload = payload[:1000]

                    start = time.time()
                    resp = await asyncio.wait_for(
                        connector.send(payload),
                        timeout=30.0  # 30 second timeout
                    )
                    elapsed = time.time() - start

                    # Check for potential DoS indicators
                    is_vulnerable = False
                    vulnerability_reason = ""

                    # Significant slowdown (5x baseline)
                    if elapsed > self.baseline_time * 5:
                        is_vulnerable = True
                        vulnerability_reason = f"Slow response: {elapsed:.2f}s (baseline: {self.baseline_time:.2f}s)"

                    # Very long response (potential token exhaustion worked)
                    if len(resp) > 10000:
                        is_vulnerable = True
                        vulnerability_reason = f"Large response: {len(resp)} chars"
                        self.last_eval_reason = vulnerability_reason

                    if is_vulnerable:
                        self.stats['success'] += 1 # Changed 'vulnerable' to 'success'
                        self._print('success', '', p['name'], response=resp)
                        self._print('detail', vulnerability_reason)

                        finding = Finding(
                            title=f"DoS - {p['name']}",
                            severity=p['severity'],
                            technique=p['name'],
                            payload=payload[:200],
                            response=f"{vulnerability_reason}. Response preview: {resp[:5000]}",
                            target=self.target,
                            reason=self.last_eval_reason,
                            owasp=p.get('owasp', [])
                        )
                        self.findings.append(finding)

                        self.db.add_result(
                            self.target, 'dos', p['name'],
                            'success', payload[:200],
                            vulnerability_reason, p['severity'].value,
                            owasp=p.get('owasp', [])
                        )
                    else:
                        self.stats['blocked'] += 1
                        self._print('blocked', '', p['name'])

                except asyncio.TimeoutError:
                    self.stats['timeouts'] += 1
                    self._print('timeout', '', p['name'])

                    # Timeout itself could indicate DoS success
                    finding = Finding(
                        title=f"DoS - {p['name']} (Timeout)",
                        severity=Severity.HIGH,
                        technique=p['name'],
                        payload=p['payload'][:200],
                        response="Request timed out after 30s - potential DoS",
                        target=self.target
                    )
                    self.findings.append(finding)
                    self.stats['success'] += 1 # Changed 'vulnerable' to 'success'

                except Exception as e:
                    self.stats['blocked'] += 1
                    if self.verbose:
                        self._print('blocked', str(e)[:50], p['name'])

                await asyncio.sleep(0.5)  # Delay between tests

        finally:
            await connector.close()

        # Print summary
        if self.stats['success'] > 0 or self.stats['timeouts'] > 0:
            self._print('warning', f"Potential DoS vulnerabilities: {self.stats['success']} found, {self.stats['timeouts']} timeouts")
        else:
            self._print('info', 'No obvious DoS vulnerabilities detected')

        self._print('info', f"{self.stats['success']} vulnerable, {self.stats['blocked']} blocked, {self.stats['timeouts']} timeouts")

        return self.findings


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(DoSScanner, target, api_key=api_key, **kwargs)
