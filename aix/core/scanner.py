"""
Base Scanner Module - Common logic for all AIX scanners
"""
import json
import os
from typing import Any, Optional

from rich.console import Console

from aix.core.connector import APIConnector, RequestConnector
from aix.core.evaluator import LLMEvaluator
from aix.core.reporter import Severity
from aix.core.request_parser import ParsedRequest
from aix.db.database import AIXDatabase

console = Console()

class BaseScanner:
    """Base class for all AIX scanners to reduce code duplication"""

    def __init__(self, target: str, api_key: str | None = None, verbose: int = 0,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.parsed_request = parsed_request

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

        self.timeout = kwargs.get('timeout', 30)

        # State
        self.findings = []
        self.stats = {'total': 0, 'success': 0, 'blocked': 0}
        self.db = AIXDatabase()
        self.payloads = []

        # Evaluator
        self.eval_config = kwargs.get('eval_config')
        self.evaluator = None
        if self.eval_config and (self.eval_config.get('url') or self.eval_config.get('provider')):
             # Inject proxy into eval config if set
             if self.proxy:
                 self.eval_config['proxy'] = self.proxy

             self.evaluator = LLMEvaluator(**self.eval_config)
             console.print(f"[bold green][*] LLM-as-a-Judge ENABLED: {self.eval_config.get('provider') or 'custom'} ({self.eval_config.get('model') or 'default'})[/bold green]")

        self.last_eval_reason = None

        # Module specific config (override in subclass)
        self.module_name = "BASE"
        self.console_color = "white"

    def load_payloads(self, filename: str) -> list[dict]:
        """Load payloads from JSON file in ../payloads directory with filtering"""
        payload_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', filename)
        try:
            with open(payload_path) as f:
                payloads = json.load(f)

            filtered_payloads = []
            for p in payloads:
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
                    filtered_payloads.append(p)


            self._print('info', f"Config: Level={self.level}, Risk={self.risk} - Loaded {len(filtered_payloads)}/{len(payloads)} payloads")
            return filtered_payloads
        except Exception as e:
            console.print(f"[yellow][!] Could not load payloads from {payload_path}: {e}[/yellow]")
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
                response_regex=self.response_regex
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
                response_regex=self.response_regex
            )

    def _print(self, status: str, msg: str, tech: str = ''):
        """Standardized formatted printing"""
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
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [{self.console_color}][*][/{self.console_color}] {msg}")
        elif status == 'success':
            # Fixed: Include msg/reason in success output
            reason_str = f" [dim]({msg})[/dim]" if msg else ""
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {tech} [bold green](Vulnerable!)[/bold green]{reason_str}")
        elif status == 'detail':
            # Details are shown if verbose >= 1 ? Usually details are useful.
            # But "only vulnerable" implies hiding details too?
            # User didn't specify details. Let's keep details if verbose >= 1 to match "vulnerable + evaluation" (evaluation is detail?)
            # Actually, `msg` contains the eval reason now.
            # The 'detail' status is used for things like "Category: ..." in agent.py.
            # Let's show details only if verbose >= 1.
            if self.verbose >= 1:
                console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30}        [dim]└─→ {msg}[/dim]")
        elif status == 'warning':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'blocked':
             # Show blocked only if verbose >= 2
             if self.verbose >= 2:
                 reason_str = f" [dim]({msg})[/dim]" if msg else ""
                 console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][-][/red] {tech} [red](Blocked)[/red]{reason_str}")
        elif status == 'error':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][!][/red] {msg}")

    async def check_success(self, response: str, indicators: list[str], payload: str, technique: str) -> bool:
        """
        Check if the attack was successful.
        Uses LLM Evaluator if available, otherwise falls back to string matching.
        """
        # Reset reason
        self.last_eval_reason = None

        # 1. Use Evaluator if available
        if self.evaluator:
            result = await self.evaluator.evaluate(response, payload, technique)
            self.last_eval_reason = result.get('reason')
            if result.get('vulnerable'):
                return True
            else:
                return False

        # 2. Fallback to keywords
        success = any(i.lower() in response.lower() for i in indicators)
        if success:
             self.last_eval_reason = "Matched indicator found in response."
        return success

    async def run(self):
        """Main execution method - usually overridden by subclasses but can provide skeleton"""
        raise NotImplementedError("Subclasses must implement run()")

    async def cleanup(self):
        """Cleanup resources"""
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
