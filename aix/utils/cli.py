"""
CLI Utilities - Common options and helpers
"""
import click
import functools

def common_options(func):
    """
    Decorator that adds common AIX CLI options to a command.
    Includes target, request parsing, authentication, and output options.
    """
    @click.argument('target', required=False)
    @click.option('--request', '-r', help='Request file (Burp Suite format)')
    @click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
    @click.option('--key', '-k', help='API key for direct API access')
    @click.option('--profile', '-P', help='Use saved profile')
    @click.option('--verbose', '-v', count=True, help='Verbose output (-v: reasons, -vv: debug)')
    @click.option('--output', '-o', help='Output file for results')
    @click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
    @click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
    @click.option('--headers', '-H', help='Custom headers (key:value; ...)')
    @click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

def refresh_options(func):
    """
    Decorator that adds session refresh options.
    """
    @click.option('--refresh-url', help='URL to fetch new session ID if expired')
    @click.option('--refresh-regex', help='Regex to extract session ID from refresh response')
    @click.option('--refresh-param', help='Parameter to update with new session ID')
    @click.option('--refresh-error', help='String/Regex in response body that triggers refresh')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

def eval_options(func):
    """
    Decorator that adds LLM evaluation options.
    """
    @click.option('--eval-url', help='URL for secondary LLM evaluation')
    @click.option('--eval-key', help='API key for secondary LLM')
    @click.option('--eval-model', help='Model for secondary LLM')
    @click.option('--eval-provider', help='Provider for secondary LLM (openai, anthropic, ollama, gemini)')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

def scan_options(func):
    """
    Decorator that adds common scan configuration options.
    """
    @click.option('--level', type=int, default=1, help='Level of tests to perform (1-5)')
    @click.option('--risk', type=int, default=1, help='Risk of tests to perform (1-3)')
    @click.option('--show-response', is_flag=True, help='Show AI response for findings')
    @click.option('--verify-attempts', '-va', type=int, default=1, help='Number of verification attempts (confirmation)')
    @click.option('--response-regex', '-rr', help='Regex to extract specific content from response (matches last occurrence)')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

def standard_options(func):
    """
    Combines all standard options: common, refresh, eval, and scan.
    """
    @common_options
    @refresh_options
    @eval_options
    @scan_options
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper
