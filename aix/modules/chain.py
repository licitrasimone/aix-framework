"""
AIX Chain Module - Attack chain execution from YAML playbooks

This module provides the interface for running attack chains defined
in YAML playbook files.
"""
import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console

from aix.core.chain import ChainExecutor, ChainResult, print_chain_summary
from aix.core.context import ChainContext
from aix.core.playbook import (
    Playbook,
    PlaybookParser,
    PlaybookError,
    find_playbook,
    list_builtin_playbooks,
)
from aix.core.reporter import Reporter
from aix.core.scanner import BaseScanner
from aix.core.visualizer import (
    PlaybookVisualizer,
    DryRunVisualizer,
    LiveChainVisualizer,
    MermaidExporter,
    print_execution_summary,
)


console = Console()


class ChainScanner(BaseScanner):
    """
    Scanner wrapper for chain execution.

    Allows chains to be run through the standard scanner interface.
    """

    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: bool = False,
        playbook_path: str | None = None,
        var_overrides: dict | None = None,
        live_viz: bool = True,
        **kwargs
    ):
        super().__init__(target, api_key, verbose, **kwargs)
        self.module_name = "CHAIN"
        self.console_color = "bright_magenta"
        self.playbook_path = playbook_path
        self.var_overrides = var_overrides or {}
        self.live_viz = live_viz
        self.chain_result: ChainResult | None = None

    async def run(self):
        """Execute the chain playbook."""
        if not self.playbook_path:
            self._print('error', "No playbook specified")
            return self.findings

        # Find and parse playbook
        path = find_playbook(self.playbook_path)
        if not path:
            self._print('error', f"Playbook not found: {self.playbook_path}")
            return self.findings

        parser = PlaybookParser()
        try:
            playbook = parser.parse(path)
        except PlaybookError as e:
            self._print('error', f"Failed to parse playbook: {e}")
            return self.findings

        self._print('info', f"Running playbook: {playbook.name}")
        self._print('info', f"Steps: {len(playbook.steps)}, Variables: {len(playbook.variables)}")

        # Create visualizer if enabled
        visualizer = LiveChainVisualizer(self.console) if self.live_viz else None

        # Create executor
        executor = ChainExecutor(
            target=self.target,
            api_key=self.api_key,
            verbose=1 if self.verbose else 0,
            visualizer=visualizer,
            parsed_request=self.parsed_request,
            proxy=self.proxy,
            cookies=self.cookies,
            headers=self.headers,
            injection_param=self.injection_param,
            body_format=self.body_format,
            refresh_config=self.refresh_config,
            response_regex=self.response_regex,
            eval_config=self.eval_config if hasattr(self, 'eval_config') else None,
            level=self.level,
            risk=self.risk,
            evasion=self.evasion_level,
            verify_attempts=self.verify_attempts,
            show_response=self.show_response,
            timeout=self.timeout,
        )

        # Execute chain
        self.chain_result = await executor.execute(playbook, self.var_overrides)

        # Copy findings
        self.findings = self.chain_result.findings

        # Update stats
        self.stats['total'] = self.chain_result.steps_executed
        self.stats['success'] = self.chain_result.steps_successful
        self.stats['blocked'] = self.chain_result.steps_failed

        # Print summary
        print_chain_summary(self.chain_result, self.console)

        return self.findings


def run(
    target: str = None,
    api_key: str = None,
    playbook: str = None,
    variables: dict = None,
    dry_run: bool = False,
    visualize: bool = False,
    export_mermaid: bool = False,
    mermaid_theme: str = 'default',
    mermaid_direction: str = 'TD',
    list_playbooks: bool = False,
    live: bool = True,
    verbose: bool = False,
    output: str = None,
    **kwargs
):
    """
    Run an attack chain from a playbook.

    Args:
        target: Target URL or endpoint
        api_key: API key for target
        playbook: Playbook file path or built-in name
        variables: Variable overrides (key=value dict)
        dry_run: Show execution plan without running
        visualize: Show playbook as static graph
        export_mermaid: Export as Mermaid diagram
        mermaid_theme: Mermaid theme
        mermaid_direction: Mermaid direction (TD, LR, etc.)
        list_playbooks: List available built-in playbooks
        live: Enable live visualization during execution
        verbose: Verbose output
        output: Output file path for report
        **kwargs: Additional config passed to modules
    """
    # List playbooks
    if list_playbooks:
        _list_playbooks()
        return

    # Check playbook specified
    if not playbook:
        console.print("[red][-] No playbook specified. Use --playbook or --list[/red]")
        return

    # Find and parse playbook
    path = find_playbook(playbook)
    if not path:
        console.print(f"[red][-] Playbook not found: {playbook}[/red]")
        console.print("[dim]Use --list to see available built-in playbooks[/dim]")
        return

    parser = PlaybookParser()
    try:
        pb = parser.parse(path)
    except PlaybookError as e:
        console.print(f"[red][-] Failed to parse playbook: {e}[/red]")
        return

    # Warnings from parser
    if parser.warnings:
        for warning in parser.warnings:
            console.print(f"[yellow][!] {warning}[/yellow]")

    # Static visualization
    if visualize:
        visualizer = PlaybookVisualizer(console)
        visualizer.print_static(pb)
        return

    # Mermaid export
    if export_mermaid:
        exporter = MermaidExporter(
            theme=mermaid_theme,
            direction=mermaid_direction,
        )
        mermaid = exporter.export(pb)
        print(mermaid)
        return

    # Dry run
    if dry_run:
        dry_viz = DryRunVisualizer(console)
        dry_viz.render(pb, variables)
        return

    # Check target
    if not target:
        console.print("[red][-] No target specified[/red]")
        return

    # Run chain
    scanner = ChainScanner(
        target,
        api_key=api_key,
        verbose=verbose,
        playbook_path=playbook,
        var_overrides=variables,
        live_viz=live,
        **kwargs
    )

    asyncio.run(scanner.run())

    # Export report if requested
    if output and scanner.chain_result:
        _export_report(scanner.chain_result, output, pb)


def _list_playbooks():
    """List available built-in playbooks."""
    playbooks = list_builtin_playbooks()

    if not playbooks:
        console.print("[yellow][!] No built-in playbooks found[/yellow]")
        console.print("[dim]Playbooks should be in aix/playbooks/ directory[/dim]")
        return

    console.print()
    console.print("[bold cyan]Available Playbooks[/bold cyan]")
    console.print("─" * 60)

    for pb in playbooks:
        console.print(f"\n[bold]{pb['name']}[/bold] [dim]({pb['filename']})[/dim]")
        if pb['description']:
            console.print(f"  {pb['description']}")
        console.print(f"  [dim]Steps: {pb['step_count']}, Author: {pb['author'] or 'AIX'}[/dim]")
        if pb['tags']:
            tags = ", ".join(pb['tags'])
            console.print(f"  [dim]Tags: {tags}[/dim]")

    console.print()


def _export_report(result: ChainResult, output: str, playbook: Playbook):
    """Export chain result to file."""
    output_path = Path(output)

    if output_path.suffix == '.json':
        _export_json(result, output_path)
    else:
        _export_html(result, output_path, playbook)


def _export_json(result: ChainResult, path: Path):
    """Export as JSON."""
    import json
    with open(path, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    console.print(f"[green][+] Report saved to {path}[/green]")


def _export_html(result: ChainResult, path: Path, playbook: Playbook):
    """Export as HTML with chain visualization."""
    from datetime import datetime

    # Generate Mermaid diagram
    exporter = MermaidExporter(theme='dark', direction='TD')
    mermaid_diagram = exporter.export(playbook)

    # Build findings HTML
    findings_html = ""
    for finding in result.findings:
        severity_class = finding.severity.value
        findings_html += f"""
        <div class="finding {severity_class}">
            <div class="finding-header">
                <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                <span class="finding-title">{finding.title}</span>
            </div>
            <div class="finding-body">
                <div class="finding-field">
                    <strong>Technique:</strong> {finding.technique}
                </div>
                {f'<div class="finding-field"><strong>Reason:</strong> {finding.reason}</div>' if finding.reason else ''}
                <div class="finding-field">
                    <strong>Payload:</strong>
                    <pre><code>{_escape_html(finding.payload)}</code></pre>
                </div>
                <div class="finding-field">
                    <strong>Response:</strong>
                    <pre><code>{_escape_html(finding.response[:1000])}</code></pre>
                </div>
            </div>
        </div>
        """

    # Build execution path
    path_html = " → ".join(result.execution_path)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIX Chain Report: {playbook.name}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid #2a2a3a;
            margin-bottom: 2rem;
        }}
        .logo {{
            font-family: 'Courier New', monospace;
            font-size: 1.5rem;
            color: #00d4ff;
            margin-bottom: 0.5rem;
        }}
        h1 {{ color: #00d4ff; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #888; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1a1a2a;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
            border: 1px solid #2a2a3a;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; }}
        .stat-label {{ color: #888; text-transform: uppercase; font-size: 0.7rem; }}
        .stat-card.critical .stat-value {{ color: #ff4757; }}
        .stat-card.high .stat-value {{ color: #ffa502; }}
        .stat-card.success .stat-value {{ color: #2ed573; }}
        .stat-card.duration .stat-value {{ color: #00d4ff; }}
        .section {{ margin-bottom: 2rem; }}
        .section h2 {{ color: #00d4ff; margin-bottom: 1rem; border-bottom: 1px solid #2a2a3a; padding-bottom: 0.5rem; }}
        .mermaid {{ background: #1a1a2a; padding: 2rem; border-radius: 8px; overflow: auto; }}
        .execution-path {{
            background: #1a1a2a;
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            color: #7bed9f;
            overflow-x: auto;
        }}
        .finding {{
            background: #1a1a2a;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid #2a2a3a;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem;
            background: #252535;
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .severity-badge.critical {{ background: #ff4757; color: white; }}
        .severity-badge.high {{ background: #ffa502; color: black; }}
        .severity-badge.medium {{ background: #3742fa; color: white; }}
        .severity-badge.low {{ background: #555; color: white; }}
        .finding-body {{ padding: 1rem; }}
        .finding-field {{ margin-bottom: 1rem; }}
        .finding-field strong {{ color: #00d4ff; }}
        pre {{
            background: #0a0a0f;
            padding: 1rem;
            border-radius: 4px;
            overflow: auto;
            max-height: 300px;
            margin-top: 0.5rem;
            border: 1px solid #333;
        }}
        code {{ font-family: 'Courier New', monospace; font-size: 0.9rem; color: #7bed9f; }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: #555;
            border-top: 1px solid #2a2a3a;
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">▄▀█ █ ▀▄▀</div>
            <h1>{playbook.name}</h1>
            <div class="subtitle">{playbook.description}</div>
        </header>

        <div class="stats">
            <div class="stat-card duration">
                <div class="stat-value">{result.total_duration:.1f}s</div>
                <div class="stat-label">Duration</div>
            </div>
            <div class="stat-card success">
                <div class="stat-value">{result.steps_executed}</div>
                <div class="stat-label">Steps</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{result.critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{result.high_count}</div>
                <div class="stat-label">High</div>
            </div>
        </div>

        <div class="section">
            <h2>Chain Flow</h2>
            <div class="mermaid">
{mermaid_diagram}
            </div>
        </div>

        <div class="section">
            <h2>Execution Path</h2>
            <div class="execution-path">{path_html}</div>
        </div>

        <div class="section">
            <h2>Findings ({result.total_findings})</h2>
            {findings_html if findings_html else '<p style="color: #888;">No findings.</p>'}
        </div>

        <footer>
            Generated by AIX Chain Engine<br>
            {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
</body>
</html>
    """

    with open(path, 'w') as f:
        f.write(html)

    console.print(f"[green][+] Report saved to {path}[/green]")


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;'))
