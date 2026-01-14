"""AIX Fuzz Module - Fuzzing and edge case testing"""
import asyncio
import random
import string
from typing import Optional, List, Dict, TYPE_CHECKING
from rich.console import Console
from aix.core.reporter import Severity, Finding
from aix.core.connector import APIConnector, RequestConnector
from aix.db.database import AIXDatabase

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()

# Unicode edge cases
UNICODE_FUZZ = [
    '\u0000',  # Null byte
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2028',  # Line separator
    '\u2029',  # Paragraph separator
    '\ufeff',  # BOM
    '\uffff',  # Max BMP
    '\U0001f4a9',  # Emoji (poop)
    '\U0001f600',  # Emoji (grin)
]

# Control characters
CONTROL_CHARS = [chr(i) for i in range(32)] + [chr(127)]

# Format string attacks
FORMAT_STRINGS = [
    '%s%s%s%s%s',
    '%n%n%n%n%n',
    '%x%x%x%x%x',
    '{0}{1}{2}',
    '${7*7}',
    '{{7*7}}',
    '#{7*7}',
]

# Default fuzz payloads
DEFAULT_FUZZ_PAYLOADS = [
    # Empty/null inputs
    {'name': 'empty_string', 'payload': '', 'category': 'boundary', 'severity': Severity.LOW},
    {'name': 'null_byte', 'payload': '\x00', 'category': 'boundary', 'severity': Severity.MEDIUM},
    {'name': 'whitespace_only', 'payload': '   \t\n\r   ', 'category': 'boundary', 'severity': Severity.LOW},

    # Unicode edge cases
    {'name': 'unicode_null', 'payload': 'Test\u0000message', 'category': 'unicode', 'severity': Severity.MEDIUM},
    {'name': 'unicode_zwsp', 'payload': 'Test\u200bmessage', 'category': 'unicode', 'severity': Severity.LOW},
    {'name': 'unicode_bom', 'payload': '\ufeffTest message', 'category': 'unicode', 'severity': Severity.LOW},
    {'name': 'unicode_rtl', 'payload': 'Test \u202emessage\u202c reversed', 'category': 'unicode', 'severity': Severity.MEDIUM},
    {'name': 'unicode_emoji', 'payload': 'Test message with emoji: \U0001F600\U0001F4A9\U0001F525', 'category': 'unicode', 'severity': Severity.LOW},
    {'name': 'unicode_zalgo', 'payload': 'T\u0336e\u0336s\u0336t\u0336 \u0336m\u0336e\u0336s\u0336s\u0336a\u0336g\u0336e\u0336', 'category': 'unicode', 'severity': Severity.LOW},

    # Encoding attacks
    {'name': 'url_encoded', 'payload': '%54%65%73%74%20%6d%65%73%73%61%67%65', 'category': 'encoding', 'severity': Severity.LOW},
    {'name': 'double_url_encoded', 'payload': '%2554%2565%2573%2574', 'category': 'encoding', 'severity': Severity.MEDIUM},
    {'name': 'html_entities', 'payload': '&lt;script&gt;alert(1)&lt;/script&gt;', 'category': 'encoding', 'severity': Severity.MEDIUM},
    {'name': 'unicode_escape', 'payload': '\\u0054\\u0065\\u0073\\u0074', 'category': 'encoding', 'severity': Severity.LOW},

    # Format strings
    {'name': 'format_string_s', 'payload': 'Test %s %s %s %s %s', 'category': 'format', 'severity': Severity.MEDIUM},
    {'name': 'format_string_n', 'payload': 'Test %n %n %n', 'category': 'format', 'severity': Severity.HIGH},
    {'name': 'format_string_x', 'payload': 'Test %x %x %x %x', 'category': 'format', 'severity': Severity.MEDIUM},
    {'name': 'python_format', 'payload': 'Test {0} {1} {__class__}', 'category': 'format', 'severity': Severity.HIGH},
    {'name': 'template_injection', 'payload': 'Test ${7*7} #{7*7} {{7*7}}', 'category': 'format', 'severity': Severity.HIGH},

    # Length boundaries
    {'name': 'very_long', 'payload': 'A' * 10000, 'category': 'length', 'severity': Severity.MEDIUM},
    {'name': 'many_words', 'payload': ' '.join(['word'] * 5000), 'category': 'length', 'severity': Severity.MEDIUM},
    {'name': 'many_lines', 'payload': '\n'.join(['line'] * 1000), 'category': 'length', 'severity': Severity.MEDIUM},

    # Special characters
    {'name': 'special_chars', 'payload': '!@#$%^&*()_+-=[]{}|;\':",./<>?`~', 'category': 'special', 'severity': Severity.LOW},
    {'name': 'backslash_heavy', 'payload': '\\\\\\\\\\test\\n\\r\\t\\\\', 'category': 'special', 'severity': Severity.MEDIUM},
    {'name': 'quote_heavy', 'payload': '"""\'\'\'`````', 'category': 'special', 'severity': Severity.MEDIUM},

    # JSON edge cases
    {'name': 'json_nested', 'payload': '{"a":' * 100 + '1' + '}' * 100, 'category': 'json', 'severity': Severity.MEDIUM},
    {'name': 'json_unicode', 'payload': '{"key": "\\u0000\\u200b\\ufeff"}', 'category': 'json', 'severity': Severity.MEDIUM},
    {'name': 'json_number', 'payload': '{"num": 99999999999999999999999999999999}', 'category': 'json', 'severity': Severity.LOW},

    # XML/markup
    {'name': 'xml_entity', 'payload': '<!DOCTYPE foo [<!ENTITY xxe "test">]>&xxe;', 'category': 'xml', 'severity': Severity.HIGH},
    {'name': 'cdata', 'payload': '<![CDATA[<script>alert(1)</script>]]>', 'category': 'xml', 'severity': Severity.MEDIUM},
    {'name': 'comment', 'payload': '<!-- comment --> test <!-- another -->', 'category': 'xml', 'severity': Severity.LOW},

    # Path traversal
    {'name': 'path_traversal', 'payload': '../../../etc/passwd', 'category': 'path', 'severity': Severity.HIGH},
    {'name': 'path_null', 'payload': '../../../etc/passwd\x00.txt', 'category': 'path', 'severity': Severity.HIGH},
    {'name': 'path_encoded', 'payload': '..%2f..%2f..%2fetc%2fpasswd', 'category': 'path', 'severity': Severity.HIGH},

    # Command injection
    {'name': 'cmd_semicolon', 'payload': 'test; ls -la', 'category': 'injection', 'severity': Severity.HIGH},
    {'name': 'cmd_pipe', 'payload': 'test | cat /etc/passwd', 'category': 'injection', 'severity': Severity.HIGH},
    {'name': 'cmd_backtick', 'payload': 'test `id`', 'category': 'injection', 'severity': Severity.HIGH},
    {'name': 'cmd_subshell', 'payload': 'test $(whoami)', 'category': 'injection', 'severity': Severity.HIGH},
]


class FuzzScanner:
    def __init__(self, target: str, api_key: Optional[str] = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, iterations: int = 100, **kwargs):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.parsed_request = parsed_request
        self.iterations = iterations
        self.findings = []
        self.stats = {'total': 0, 'anomalies': 0, 'errors': 0, 'blocked': 0}
        self.db = AIXDatabase()
        self.baseline_response = None

    def _print(self, status: str, msg: str, tech: str = ''):
        t = self.target[:28] + '...' if len(self.target) > 30 else self.target
        if status == 'info':
            console.print(f"[cyan]FUZZ[/cyan]    {t:30} [cyan][*][/cyan] {msg}")
        elif status == 'success':
            console.print(f"[cyan]FUZZ[/cyan]    {t:30} [green][+][/green] {tech} [bold green](Anomaly!)[/bold green]")
        elif status == 'detail':
            console.print(f"[cyan]FUZZ[/cyan]    {t:30}        [dim]└─→ {msg}[/dim]")
        elif status == 'warning':
            console.print(f"[cyan]FUZZ[/cyan]    {t:30} [yellow][!][/yellow] {msg}")
        elif status == 'error':
            console.print(f"[cyan]FUZZ[/cyan]    {t:30} [red][-][/red] {msg}")
        elif status == 'progress':
            console.print(f"[dim]Fuzz iteration {msg}[/dim]")

    def _generate_random_fuzz(self) -> List[Dict]:
        """Generate random fuzz payloads"""
        payloads = []

        # Random unicode strings
        for i in range(10):
            chars = [random.choice(UNICODE_FUZZ) for _ in range(random.randint(1, 10))]
            payloads.append({
                'name': f'random_unicode_{i}',
                'payload': 'Test ' + ''.join(chars) + ' message',
                'category': 'random_unicode',
                'severity': Severity.LOW
            })

        # Random control characters
        for i in range(5):
            chars = [random.choice(CONTROL_CHARS) for _ in range(random.randint(1, 5))]
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
        if payloads is None:
            payloads = DEFAULT_FUZZ_PAYLOADS.copy()

        # Add random fuzzing if iterations are high
        if self.iterations > len(payloads):
            random_payloads = self._generate_random_fuzz()
            payloads.extend(random_payloads)

        # Limit to iterations count
        payloads = payloads[:self.iterations]

        self._print('info', f'Running {len(payloads)} fuzz tests...')

        # Create connector
        if self.parsed_request:
            connector = RequestConnector(self.parsed_request)
        else:
            connector = APIConnector(self.target, api_key=self.api_key)

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
                        self.stats['anomalies'] += 1
                        self._print('success', '', p['name'])
                        for detail in anomaly_details[:3]:
                            self._print('detail', detail)

                        finding = Finding(
                            title=f"Fuzz Anomaly - {p['name']}",
                            severity=p['severity'],
                            technique=p['name'],
                            payload=p['payload'][:200] if len(p['payload']) < 500 else f"{p['payload'][:100]}... ({len(p['payload'])} chars)",
                            response=resp[:500],
                            target=self.target
                        )
                        self.findings.append(finding)

                        self.db.add_result(
                            self.target, 'fuzz', p['name'],
                            'anomaly', p['payload'][:200],
                            resp[:500], p['severity'].value
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
        if self.stats['anomalies'] > 0:
            self._print('warning', f"Found {self.stats['anomalies']} anomalies!")
        else:
            self._print('info', 'No anomalies detected')

        self._print('info', f"{self.stats['anomalies']} anomalies, {self.stats['errors']} errors, {self.stats['blocked']} normal")

        return self.findings


def run(target: str = None, api_key: str = None, profile: str = None, browser: bool = False,
        iterations: int = 100, verbose: bool = False, output: str = None,
        parsed_request: Optional['ParsedRequest'] = None, **kwargs):
    if not target:
        console.print("[red][-][/red] No target specified")
        return

    scanner = FuzzScanner(
        target, api_key=api_key, verbose=verbose,
        parsed_request=parsed_request, iterations=iterations
    )
    asyncio.run(scanner.run())


__all__ = ["run"]
