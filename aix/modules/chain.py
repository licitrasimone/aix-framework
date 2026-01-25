"""
AIX Chain Module - Attack chain execution from YAML playbooks

This module provides the interface for running attack chains defined
in YAML playbook files.
"""
import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console

from aix.core.chain_engine.executor import ChainExecutor, ChainResult, print_chain_summary
from aix.core.chain_engine.context import ChainContext
from aix.core.chain_engine.playbook import (
    Playbook,
    PlaybookParser,
    PlaybookError,
    find_playbook,
    list_builtin_playbooks,
)
from aix.core.reporting.chain import ChainReporter
from aix.core.reporting.base import Reporter
from aix.core.scanner import BaseScanner
from aix.core.reporting.visualizer import (
    PlaybookVisualizer,
    DryRunVisualizer,
    LiveChainVisualizer,
    MermaidExporter,
    CytoscapeExporter,
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
        self.show_progress = True  # Always show progress in module steps
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
        # Note: level, risk, evasion come from playbook variables (or -V overrides),
        # not from CLI options. Each step interpolates {{level}}, {{risk}}, {{evasion}}.
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
            verify_attempts=self.verify_attempts,
            show_response=self.show_response,
            timeout=self.timeout,
            console=self.console,
            show_progress=self.show_progress,
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
        reporter = ChainReporter()
        reporter.export_report(scanner.chain_result, output, pb)


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

