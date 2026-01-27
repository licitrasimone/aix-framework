"""
Base Scanner Module - Common logic for all AIX scanners
"""
import json
import asyncio
import os
from typing import Any, Optional
from abc import ABC

from rich.console import Console

from aix.core.connector import APIConnector, RequestConnector
from aix.core.evasion import PayloadEvasion
from aix.core.evaluator import LLMEvaluator
from aix.core.ai_engine import AIEngine
from aix.core.context import TargetContext
from aix.core.owasp import OWASPCategory, get_owasp_for_module, parse_owasp_list
from aix.core.reporting.base import Severity
from aix.core.request_parser import ParsedRequest
from aix.db.database import AIXDatabase


class CircuitBreakerError(Exception):
    """Raised when scan should be aborted due to excessive errors"""
    pass

class BaseScanner(ABC):
    """Base class for all AIX scanners to reduce code duplication"""

    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, timeout: int = 30, browser: bool = False, console: Console | None = None, **kwargs):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.parsed_request = parsed_request
        self.timeout = timeout # Set from parameter
        self.browser = browser
        self.show_response = kwargs.get('show_response', False)
        # Always show progress unless explicitly disabled (default True)
        self.show_progress = kwargs.get('show_progress', True)

        # Quiet mode suppresses text output but keeps progress bars (used in chain mode)
        self.quiet = kwargs.get('quiet', False)
        self.console = console if console else Console()

        # Common optional arguments
        self.proxy = kwargs.get('proxy')
        self.cookies = kwargs.get('cookies')
        self.headers = kwargs.get('headers')
        self.injection_param = kwargs.get('injection_param')
        self.body_format = kwargs.get('body_format')
        self.body_format = kwargs.get('body_format')
        self.refresh_config = kwargs.get('refresh_config')
        self.response_regex = kwargs.get('response_regex')

        # Filtering config
        self.level = kwargs.get('level', 1)
        self.risk = kwargs.get('risk', 1)
        self.verify_attempts = kwargs.get('verify_attempts', 1)

        # Evasion config
        self.evasion_level = kwargs.get('evasion', 'none')
        self.evasion = PayloadEvasion(self.evasion_level)

        self.timeout = kwargs.get('timeout', 30)

        # State
        self.findings = []
        self.stats = {'total': 0, 'success': 0, 'blocked': 0}
        self.db = AIXDatabase()
        self.payloads = []
        
        # Circuit Breaker State
        self.consecutive_errors = 0
        self.circuit_breaker_limit = 10 

        # AI Engine (unified evaluator + context)
        self.ai_config = kwargs.get('ai_config')
        self.ai_engine: AIEngine | None = None
        self.context: TargetContext | None = None

        if self.ai_config and self.ai_config.get('provider'):
            # Inject proxy into config if set
            if self.proxy:
                self.ai_config['proxy'] = self.proxy

            self.ai_engine = AIEngine(**self.ai_config)
            if not self.quiet:
                features = []
                if self.ai_config.get('enable_eval', True):
                    features.append("Eval")
                if self.ai_config.get('enable_context', True):
                    features.append("Context")
                self.console.print(f"[bold green][*] AI Engine ENABLED: {self.ai_config.get('provider')} ({', '.join(features)})[/bold green]")

        # Legacy evaluator support (backward compatibility)
        self.eval_config = kwargs.get('eval_config')
        self.evaluator = None
        if not self.ai_engine and self.eval_config and (self.eval_config.get('url') or self.eval_config.get('provider')):
             # Inject proxy into eval config if set
             if self.proxy:
                 self.eval_config['proxy'] = self.proxy

             self.evaluator = LLMEvaluator(**self.eval_config)
             if not self.quiet:
                 self.console.print(f"[bold green][*] LLM-as-a-Judge ENABLED: {self.eval_config.get('provider') or 'custom'} ({self.eval_config.get('model') or 'default'})[/bold green]")

        # Module specific config (default, can be overridden)
        self.module_name = "BASE"
        self.console_color = "white"

        self.last_eval_reason = None
        # Load refusals but disable them if LLM judge is active (user preference: LLM > refusals)
        self.refusals = self.load_payloads('refusals.json', quiet=True) if not self.evaluator else []

    def _update_error_state(self, error_str: str | None = None):
        """Update consecutive error count and check circuit breaker"""
        if error_str and ("403" in error_str or "500" in error_str):
            self.consecutive_errors += 1
        else:
            self.consecutive_errors = 0 # Reset on success or non-critical error
            
        if self.consecutive_errors >= self.circuit_breaker_limit:
            msg = f"Scan aborted: Exceeded {self.circuit_breaker_limit} consecutive critical errors (WAF block prevented?)"
            self._print('error', msg)
            raise CircuitBreakerError(msg)

    def load_payloads(self, filename: str, quiet: bool = False) -> list[dict]:
        """Load payloads from JSON file in ../payloads directory with filtering"""
        payload_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', filename)
        # self.console.print(f"[debug] Loading {filename} from {payload_path}")
        try:
            with open(payload_path) as f:
                payloads = json.load(f)
                # self.console.print(f"[debug] Parsed JSON for {filename}: {len(payloads)} items")

            filtered_payloads = []
            for p in payloads:
                # Default values if missing

                if isinstance(p, str):
                   # Handle simple string lists (like refusals.json)
                   filtered_payloads.append(p)
                   continue

                # Default values if missing
                curr_level = p.get('level', 1)
                curr_risk = p.get('risk', 1)

                # Filter logic: include if payload level/risk <= user requested level/risk
                if curr_level <= self.level and curr_risk <= self.risk:
                    # Reconstruct Severity objects
                    if isinstance(p.get('severity'), str):
                        try:
                            p['severity'] = Severity[p['severity']]
                        except KeyError:
                            p['severity'] = Severity.MEDIUM

                    # Parse OWASP categories
                    if 'owasp' in p and isinstance(p['owasp'], list):
                        p['owasp'] = parse_owasp_list(p['owasp'])
                    else:
                        # Default from module mapping
                        p['owasp'] = get_owasp_for_module(self.module_name.lower())

                    filtered_payloads.append(p)


            # Apply evasion to payloads if enabled
            if self.evasion_level != 'none':
                for p in filtered_payloads:
                    if isinstance(p, dict) and 'payload' in p:
                        p['original_payload'] = p['payload']  # Keep original for logging
                        p['payload'] = self.evasion.evade(p['payload'])

            if not quiet:
                evasion_str = f", Evasion={self.evasion_level}" if self.evasion_level != 'none' else ""
                self._print('info', f"Config: Level={self.level}, Risk={self.risk}{evasion_str} - Loaded {len(filtered_payloads)}/{len(payloads)} payloads")
            return filtered_payloads
        except Exception as e:
            if not self.quiet:
                self.console.print(f"[yellow][!] Could not load payloads from {payload_path}: {e}[/yellow]")
            return []

    def _init_stats(self, **kwargs):
        """Update stats dictionary with default values"""
        self.stats.update(kwargs)

    def _create_connector(self):
        """Create the appropriate connector based on configuration"""
        if self.parsed_request:
            return RequestConnector(
                self.parsed_request,
                proxy=self.proxy,
                verbose=self.verbose,
                cookies=self.cookies,
                headers=self.headers,
                timeout=self.timeout,
                refresh_config=self.refresh_config,
                response_regex=self.response_regex,
                console=self.console
            )
        else:
            return APIConnector(
                self.target,
                api_key=self.api_key,
                proxy=self.proxy,
                verbose=self.verbose,
                cookies=self.cookies,
                headers=self.headers,
                injection_param=self.injection_param,
                body_format=self.body_format,
                timeout=self.timeout,
                refresh_config=self.refresh_config,
                response_regex=self.response_regex,
                console=self.console
            )

    def _print(self, status: str, msg: str, tech: str = '', response: str = None):
        """Standardized formatted printing"""
        # In quiet mode (chain execution), suppress text output but keep progress bars
        if self.quiet:
            return

        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        name = self.module_name[:7].upper() # Limit length

        # Append evaluator reason if available and relevant
        # Only append for verdicts to avoid polluting detailed logs
        # Logic:
        # Level 0 (default): No reasons
        # Level 1 (-v): Show reasons
        # Level 2 (-vv): Show reasons + blocked

        should_show_reason = self.verbose >= 1

        if should_show_reason and self.last_eval_reason and status in ['success', 'blocked', 'warning']:
            if msg:
                msg += f" - {self.last_eval_reason}"
            else:
                msg = f"Evaluator: {self.last_eval_reason}"

        if status == 'info':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [{self.console_color}][*][/{self.console_color}] {msg}")
        elif status == 'success':
            # Fixed: Include msg/reason in success output
            reason_str = f" [dim]({msg})[/dim]" if msg else ""
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {tech} [bold green](Vulnerable!)[/bold green]{reason_str}")
            if self.show_response and response:
                self.console.print(f"        [dim]Response: {response[:500].replace('[', r'\[')}[/dim]")
        elif status == 'detail':
            # Details are shown if verbose >= 1 ? Usually details are useful.
            # But "only vulnerable" implies hiding details too?
            # User didn't specify details. Let's keep details if verbose >= 1 to match "vulnerable + evaluation" (evaluation is detail?)
            # Actually, `msg` contains the eval reason now.
            # The 'detail' status is used for things like "Category: ..." in agent.py.
            # Let's show details only if verbose >= 1.
            if self.verbose >= 1:
                self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30}        [dim]└─→ {msg}[/dim]")
        elif status == 'warning':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'blocked':
             # Show blocked only if verbose >= 2
             if self.verbose >= 2:
                 reason_str = f" [dim]({msg})[/dim]" if msg else ""
                 self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][-][/red] {tech} [red](Blocked)[/red]{reason_str}")
        elif status == 'error':
            self.console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][!][/red] {msg}")

    async def _check_refusal(self, response: str) -> bool:
        """Check if response contains refusal patterns"""
        response_lower = response.lower()
        # self.console.print(f"[debug] Checking refusal for: {response_lower[:50]}...")
        # self.console.print(f"[debug] Against {len(self.refusals)} patterns: {self.refusals}")
        for r in self.refusals:
            # refusals.json is a list of strings
            if isinstance(r, str) and r.lower() in response_lower: 
                # self.console.print(f"[debug] MATCHED REFUSAL: {r}")
                return True
        return False

    async def check_success(self, response: str, indicators: list[str], payload: str, technique: str) -> bool:
        """
        Check if the attack was successful.
        Uses AI Engine or LLM Evaluator if available, otherwise falls back to string matching.
        """
        # Reset reason
        self.last_eval_reason = None

        # 1. Use AI Engine if available (new unified system)
        if self.ai_engine and self.ai_engine.enable_eval:
            result = await self.ai_engine.evaluate(response, payload, technique)
            self.last_eval_reason = result.get('reason')
            return result.get('vulnerable', False)

        # 2. Use legacy Evaluator if available
        if self.evaluator:
            result = await self.evaluator.evaluate(response, payload, technique)
            self.last_eval_reason = result.get('reason')
            if result.get('vulnerable'):
                return True
            else:
                return False

        # 3. Fallback to keywords
        success = any(i.lower() in response.lower() for i in indicators)

        # Check for refusals if no evaluator is used
        if success and await self._check_refusal(response):
             self.last_eval_reason = "Blocked by refusal check (False Positive)"
             # Treat as blocked/safe if it's a known refusal, unless indicators are very specific?
             # User requested to avoid opening vuln for 'i cannot provide'.
             # So we flip success to False.
             return False

        if success:
             self.last_eval_reason = "Matched indicator found in response."
        return success

    async def verify_result(self, response: str, connector, payload: str, indicators: list[str], technique: str) -> bool:
        """
        [DEPRECATED] Use scan_payload instead.
        Keep for backward compatibility during refactor.
        """
        return await self.check_success(response, indicators, payload, technique)

    async def scan_payload(self, connector, payload: str, indicators: list[str], technique: str) -> tuple[bool, str]:
        """
        Robust payload scanning.
        Sends payload `verify_attempts` times.
        Returns: (is_vulnerable, best_response)
        
        Logic:
        - If verify_attempts > 1:
            - Try N times.
            - If ANY attempt succeeds -> Vulnerable.
            - If ALL fail -> Blocked.
            - Calculate success rate.
        - If verify_attempts == 1:
            - Try once.
        """
        attempts = self.verify_attempts
        successes = 0
        failures = 0
        best_response = None
        
        # If default 1 attempt, use fast path
        if attempts <= 1:
            resp = await connector.send(payload)
            success = await self.check_success(resp, indicators, payload, technique)
            return success, resp

        # Robust loop
        if self.verbose >= 2:
            self._print('info', f"Probing {technique} ({attempts} attempts)...")
        
        for i in range(attempts):
            try:
                resp = await connector.send(payload)
                if not resp:
                    resp = "" # Handle empty
                
                success = await self.check_success(resp, indicators, payload, technique)
                
                if success:
                    successes += 1
                    best_response = resp # Prefer successful response
                    # Optimization: If user didn't ask for full rigorous stats, maybe stop?
                    # User said "sent always n attempts". So we continue.
                else:
                    failures += 1
                    if not best_response:
                        best_response = resp # Keep at least one response (even failure)
            
            except Exception as e:
                failures += 1
                if not best_response:
                     best_response = f"Error: {str(e)}"
                
                # Check for critical errors (403, etc.)
                error_str = str(e)
                if "403" in error_str:
                     self._print('error', f"Target returned 403 Forbidden ({technique})")
                     self._update_error_state(error_str)
                elif "500" in error_str:
                     self._print('error', f"Target returned 500 Server Error ({technique})")
                     self._update_error_state(error_str)
                elif self.verbose >= 1 and not self.quiet: # Print other errors if verbose
                     self.console.print(f"[yellow][!] Error probing {technique}: {e}[/yellow]")
                     self._update_error_state(None) # Reset if generic error? Or ignore? 
                     # Let's reset for generic errors to be safe, or only pure successes?
                     # Ideally 403 is the blocker. If we get a connection error, maybe we shouldn't reset.
                     # But for now, let's only increment on 403/500 as per logic.
                     # Calling with None resets.
                     pass

        # Decision Logic
        if successes > 0:
            self._update_error_state(None) # Reset count on any success
            if successes < attempts:
                 self._print('warning', f"{technique}: Unstable exploit ({successes}/{attempts} successes)")
            else:
                 self._print('info', f"{technique}: robust ({successes}/{attempts} successes)")
            return True, best_response
        else:
            return False, best_response

    async def run(self):
        """Main execution method - usually overridden by subclasses but can provide skeleton"""
        raise NotImplementedError("Subclasses must implement run()")

    async def gather_context(self, connector) -> TargetContext | None:
        """
        Gather context about the target before scanning.
        Only runs if AI Engine is configured with context enabled.
        """
        if not self.ai_engine:
            # No AI engine configured - context gathering not available
            return None

        if not self.ai_engine.enable_context:
            return None

        if not self.quiet:
            self._print('info', 'Gathering target context...')

        try:
            self.context = await self.ai_engine.gather_context(connector)
            if self.context and not self.context.is_empty():
                if not self.quiet:
                    if self.context.model_type:
                        self._print('info', f'Detected model: {self.context.model_type}')
                    if self.context.has_rag:
                        self._print('info', 'RAG system detected')
                    if self.context.has_tools:
                        self._print('info', 'Tool/function calling detected')
            return self.context
        except Exception as e:
            if self.verbose:
                self.console.print(f"[yellow][!] Context gathering failed: {e}[/yellow]")
            return None

    async def cleanup(self):
        """Cleanup resources"""
        if self.ai_engine:
            await self.ai_engine.close()
        if self.evaluator:
            await self.evaluator.close()

# Backward compatibility & Missing classes
class TargetProfile:
    """Target profile configuration"""
    def __init__(self, target: str):
        self.target = target

class AttackResult:
    """Attack result container"""
    def __init__(self, success: bool, data: Any = None):
        self.success = success
        self.data = data

class AttackResponse:
    """Attack response wrapper"""
    def __init__(self, response: str):
        self.response = response

AIXScanner = BaseScanner


def run_scanner(scanner_cls, target: str = None, api_key: str = None, **kwargs):
    """
    Helper to run any scanner class with asyncio.
    Handles target validation and common setup.
    """
    if not target:
        Console().print("[red][-][/red] No target specified")
        return

    # Initialize scanner with all arguments
    scanner = scanner_cls(target, api_key=api_key, **kwargs)
    
    # Run async
    return asyncio.run(scanner.run())
