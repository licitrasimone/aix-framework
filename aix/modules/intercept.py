"""AIX Intercept Module - Proxy mode for traffic analysis

Starts a simple TCP-forwarding proxy that can forward to an upstream proxy
such as Burp. Captures initial request/response bytes for inspection.
"""
import asyncio
from typing import Optional, Tuple
from rich.console import Console

from aix.core.connector import InterceptConnector

console = Console()


def _parse_proxy(proxy: Optional[str]) -> Optional[Tuple[str, int]]:
    if not proxy:
        return None
    if ':' in proxy:
        host, port = proxy.split(':', 1)
        return host, int(port)
    return (proxy, 8080)


def run(port: int = 8080, profile: str = None, output: str = None, proxy: Optional[str] = None, **kwargs):
    """Start intercept proxy and run until interrupted.

    The TCP-forwarding proxy will only start if `--proxy IP:PORT` is provided.
    """
    parsed = _parse_proxy(proxy)

    console.print(f"[cyan]INTERCEPT[/cyan] [cyan][*][/cyan] Intercept command invoked")
    if not parsed:
        console.print(f"[yellow][!][/yellow] No --proxy provided; TCP forwarding disabled. Use mitmproxy for full interception.")
        return

    console.print(f"[cyan]INTERCEPT[/cyan] [cyan][*][/cyan] Starting proxy on 127.0.0.1:{port}")
    console.print(f"[cyan]INTERCEPT[/cyan] [cyan][*][/cyan] Forwarding to upstream proxy {parsed[0]}:{parsed[1]}")
    console.print(f"[cyan]INTERCEPT[/cyan] [cyan][*][/cyan] Configure your browser to use this proxy")

    connector = InterceptConnector(url='', port=port, upstream=parsed)

    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(connector.connect())
        console.print(f"[cyan]INTERCEPT[/cyan] [green][+][/green] Proxy running. Press Ctrl-C to stop.")
        # Run forever until interrupted
        loop.run_forever()

    except KeyboardInterrupt:
        console.print(f"[cyan]INTERCEPT[/cyan] [yellow][!][/yellow] Stopping proxy...")
    finally:
        try:
            loop.run_until_complete(connector.close())
        except Exception:
            pass

    # Dump intercepted pairs to output if requested
    pairs = connector.get_intercepted()
    if output:
        import json
        with open(output, 'w', encoding='utf-8') as f:
            json.dump([{'request': r, 'response': s} for r, s in pairs], f, ensure_ascii=False, indent=2)
        console.print(f"[cyan]INTERCEPT[/cyan] [green][+][/green] Saved intercepted data to {output}")
    else:
        console.print(f"[cyan]INTERCEPT[/cyan] [cyan][*][/cyan] Captured {len(pairs)} request/response pairs")
