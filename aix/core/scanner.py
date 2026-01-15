"""
Base Scanner Module - Common logic for all AIX scanners
"""
import os
import json
import asyncio
from typing import Optional, List, Dict, Any, Union
from rich.console import Console

from aix.core.reporter import Severity, Finding
from aix.core.connector import APIConnector, RequestConnector

from aix.db.database import AIXDatabase
from aix.core.request_parser import ParsedRequest

console = Console()

class BaseScanner:
    """Base class for all AIX scanners to reduce code duplication"""
    
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
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

        self.timeout = kwargs.get('timeout', 30)
        
        # State
        self.findings = []
        self.stats = {'total': 0, 'success': 0, 'blocked': 0}
        self.db = AIXDatabase()
        self.payloads = []
        
        # Module specific config (override in subclass)
        self.module_name = "BASE"
        self.console_color = "white"

    def load_payloads(self, filename: str) -> List[Dict]:
        """Load payloads from JSON file in ../payloads directory"""
        payload_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', filename)
        try:
            with open(payload_path, 'r') as f:
                payloads = json.load(f)
            
            # Reconstruct Severity objects
            for p in payloads:
                if isinstance(p.get('severity'), str):
                    try:
                        p['severity'] = Severity[p['severity']]
                    except KeyError:
                        p['severity'] = Severity.MEDIUM
            return payloads
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
                timeout=self.timeout
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
                timeout=self.timeout
            )

    def _print(self, status: str, msg: str, tech: str = ''):
        """Standardized formatted printing"""
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        name = self.module_name[:7].upper() # Limit length
        
        if status == 'info':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [{self.console_color}][*][/{self.console_color}] {msg}")
        elif status == 'success':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {tech} [bold green](Vulnerable!)[/bold green]")
        elif status == 'detail':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30}        [dim]└─→ {msg}[/dim]")
        elif status == 'warning':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'blocked' and self.verbose:
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][-][/red] {tech} [red](Blocked)[/red]")
        elif status == 'error':
            console.print(f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][!][/red] {msg}")

    async def run(self):
        """Main execution method - usually overridden by subclasses but can provide skeleton"""
        raise NotImplementedError("Subclasses must implement run()")

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
