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
    """Export as HTML with interactive Cytoscape visualization."""
    from datetime import datetime
    from aix.core.reporter import Severity
    import json

    # Generate Graph Data
    exporter = CytoscapeExporter()
    graph_elements_json = exporter.export(playbook, result)
    
    # Count findings by severity
    counts = dict.fromkeys(Severity, 0)
    
    # Group findings by target
    findings_by_target: dict[str, list] = {}
    
    for finding in result.findings:
        counts[finding.severity] += 1
        
        target = finding.target or "Unknown Target"
        if target not in findings_by_target:
            findings_by_target[target] = []
        findings_by_target[target].append(finding)

    # Sort findings within each target by severity
    severity_order = {
        Severity.CRITICAL: 0, 
        Severity.HIGH: 1, 
        Severity.MEDIUM: 2, 
        Severity.LOW: 3, 
        Severity.INFO: 4
    }
    
    for target in findings_by_target:
        findings_by_target[target].sort(key=lambda f: severity_order.get(f.severity, 99))

    # Build findings HTML - REVERTED STYLE (Cleaner/Standard)
    findings_html = ""
    
    for target, target_findings in findings_by_target.items():
        findings_html += f'<div class="target-group"><h3>{target}</h3>'
        
        for finding in target_findings:
            severity_class = finding.severity.value
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                    <span class="finding-title">{finding.title}</span>
                    <span class="technique-badge">{finding.technique}</span>
                </div>
                <div class="finding-body">
                    {f'<div class="finding-field reason"><strong>Reason:</strong> {finding.reason}</div>' if finding.reason else ''}
                    
                    <details>
                        <summary>Payload & Response</summary>
                        <div class="finding-field">
                            <strong>Payload:</strong>
                            <pre><code>{_escape_html(finding.payload)}</code></pre>
                        </div>
                        <div class="finding-field">
                            <strong>Response:</strong>
                            <pre><code>{_escape_html(finding.response[:2000] + ('...' if len(finding.response) > 2000 else ''))}</code></pre>
                        </div>
                    </details>
                    
                     {f'<div class="finding-field"><strong>Details:</strong> {finding.details}</div>' if finding.details else ''}
                </div>
            </div>
            """
        findings_html += "</div>"

    # Build execution path
    path_html = " → ".join(result.execution_path)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIX Chain Report: {playbook.name}</title>
    
    <!-- Cytoscape Core & Dagre Layout -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>

    <style>
        /* Core Reporter CSS */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid #2a2a3a;
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-family: 'Courier New', monospace;
            font-size: 2rem;
            color: #00d4ff;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: #888;
            font-size: 1.1rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #1a1a2a;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #2a2a3a;
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        
        .stat-label {{
            color: #888;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}
        
        .stat-card.critical .stat-value {{ color: #ff4757; }}
        .stat-card.high .stat-value {{ color: #ffa502; }}
        .stat-card.medium .stat-value {{ color: #3742fa; }}
        .stat-card.low .stat-value {{ color: #888; }}
        .stat-card.duration .stat-value {{ color: #00d4ff; }} /* Custom for Chain */
        
        .section {{ margin-bottom: 3rem; }}
        .section h2 {{ 
            margin-bottom: 1rem;
            color: #00d4ff;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}

        /* Graph Specific CSS (Overlay Mode) */
        .graph-wrapper {{
            display: flex;
            gap: 0;
            height: 600px;
            background: #16161e;
            border: 1px solid #333;
            border-radius: 8px;
            overflow: hidden;
            position: relative;
        }}
        #cy {{
            flex: 1;
            height: 100%;
            background: #111118;
            z-index: 1;
        }}
        #node-details {{
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            width: 400px;
            background: rgba(26, 26, 36, 0.95);
            backdrop-filter: blur(10px);
            border-left: 1px solid #333;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            transition: transform 0.3s cubic-bezier(0.4, 0.0, 0.2, 1);
            z-index: 1000;
            transform: translateX(0);
            box-shadow: -5px 0 20px rgba(0,0,0,0.5);
        }}
        #node-details.hidden {{
            transform: translateX(100%);
            display: flex !important;
        }}
        #node-details h3 {{ 
            color: #00d4ff; 
            margin-bottom: 1rem; 
            border-bottom: 1px solid #333; 
            padding-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
        }}
        .close-btn {{ cursor: pointer; color: #888; font-size: 1.2rem; transition: color 0.2s; }}
        .close-btn:hover {{ color: #fff; }}
        
        .detail-row {{ margin-bottom: 1rem; font-size: 0.9rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.5rem; }}
        .detail-label {{ color: #888; display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
        .detail-value {{ color: #fff; font-family: 'Courier New', monospace; word-break: break-all; }}
        
        .execution-path {{
            background: #0a0a0f;
            padding: 1rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #aaa;
            overflow-x: auto;
            border: 1px solid #333;
        }}

        /* Findings CSS (Standardized) */
        .finding {{
            background: #1a1a2a;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid #2a2a3a;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem 1.5rem;
            background: #252535;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        .finding-title {{ font-weight: 600; color: #e0e0e0; }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            min-width: 80px;
            text-align: center;
        }}
        .severity-badge.critical {{ background: #ff4757; color: white; }}
        .severity-badge.high {{ background: #ffa502; color: black; }}
        .severity-badge.medium {{ background: #3742fa; color: white; }}
        .severity-badge.low {{ background: #555; color: white; }}
        
        .technique-badge {{
            background: #2a2a3a;
            color: #aaa;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
            margin-left: auto;
        }}

        .finding-body {{ padding: 1.5rem; }}
        
        .finding-field {{ margin-bottom: 1rem; }}
        .finding-field.reason {{
            background: #2a2a3a;
            padding: 0.75rem;
            border-radius: 4px;
            border-left: 3px solid #00d4ff;
        }}
        .finding-field strong {{ color: #00d4ff; }}

        pre {{
            background: #0a0a0f;
            padding: 1rem;
            border-radius: 4px;
            border: 1px solid #333;
            color: #ccc;
            overflow-x: auto;
        }}
        
        /* Custom Scrollbar */
        pre::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        pre::-webkit-scrollbar-track {{ background: #0a0a0f; }}
        pre::-webkit-scrollbar-thumb {{ background: #2a2a3a; border-radius: 4px; }}
        pre::-webkit-scrollbar-thumb:hover {{ background: #00d4ff; }}

        code {{ color: #7bed9f; font-family: 'Courier New', monospace; font-size: 0.9rem; }}
        
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
            <div class="logo">▄▀█ █ ▀▄▀<br>█▀█ █ █ █</div>
            <div class="subtitle">AIX Chain Report: {playbook.name}</div>
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
            <h2>Chain Execution Flow <span style="font-size: 0.8rem; color: #555; font-weight: normal; margin-left: 1rem;">(Click nodes for details)</span></h2>
            <div class="graph-wrapper">
                <div id="cy"></div>
                <div id="node-details">
                    <div id="details-content">
                        <p style="color: #666; margin-top: 2rem; text-align: center;">Select a step to view info.</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Execution Path</h2>
            <div class="execution-path">{path_html}</div>
        </div>

        <div class="section" id="findings-section">
            <h2>Findings ({result.total_findings})</h2>
            {findings_html if findings_html else '<p style="color: #888; font-style: italic;">No vulnerabilities found.</p>'}
        </div>

        <footer>
            Generated by AIX Chain Engine • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <script>
        const graphData = {graph_elements_json};

        document.addEventListener('DOMContentLoaded', function() {{
            cytoscape.use(cytoscapeDagre);

            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: graphData,
                
                boxSelectionEnabled: false,
                autounselectify: false,

                layout: {{
                    name: 'dagre',
                    rankDir: 'LR', // Horizontal layout
                    spacingFactor: 1.2
                }},

                style: [
                    {{
                        selector: 'node',
                        style: {{
                            'content': 'data(label)',
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'text-margin-y': 10,
                            'color': '#aaa',
                            'font-family': 'Segoe UI, sans-serif',
                            'font-size': 12,
                            'background-color': '#2a2a3a',
                            'border-width': 2,
                            'border-color': '#555',
                            'width': 40,
                            'height': 40
                        }}
                    }},
                    {{
                        selector: 'node:selected',
                        style: {{
                            'border-color': '#fff',
                            'border-width': 3,
                            'color': '#fff'
                        }}
                    }},
                    {{
                        selector: 'node[type="condition"]',
                        style: {{ 'shape': 'diamond', 'border-color': '#ffa502' }}
                    }},
                    {{
                        selector: 'node[type="report"]',
                        style: {{ 'shape': 'round-rectangle', 'border-color': '#2ed573' }}
                    }},
                    {{
                        selector: 'node[status="executed"]',
                        style: {{
                            'background-color': '#111',
                            'border-color': '#00d4ff',
                            'color': '#fff',
                            'text-shadow': '0 0 5px rgba(0,0,0,0.8)'
                        }}
                    }},
                    {{
                        selector: 'node[status="failed"]',
                        style: {{ 'border-color': '#ff4757' }}
                    }},
                    {{
                        selector: 'edge',
                        style: {{
                            'width': 2,
                            'curve-style': 'taxi',
                            'taxi-direction': 'horizontal',
                            'target-arrow-shape': 'triangle',
                            'line-color': '#333',
                            'target-arrow-color': '#333'
                        }}
                    }},
                    {{
                        selector: 'edge[type="success"]',
                        style: {{ 'line-color': '#555', 'target-arrow-color': '#555' }}
                    }}
                ]
            }});
            
            // Interaction Logic
            const detailsPanel = document.getElementById('node-details');
            const detailsContent = document.getElementById('details-content');
            
            // Initial State: Hidden (Slide out)
            detailsPanel.classList.add('hidden');
            
            cy.on('tap', 'node', function(evt){{
                console.log('Node tapped:', evt.target.id());
                const node = evt.target;
                const data = node.data();
                const details = data.details || {{}};
                
                // Show Panel (Slide in)
                requestAnimationFrame(() => {{
                    detailsPanel.classList.remove('hidden');
                }});
                
                let html = `
                    <h3>Step Details <span class="close-btn" onclick="document.getElementById('node-details').classList.add('hidden');">&times;</span></h3>
                    <div class="detail-row">
                        <span class="detail-label">ID</span>
                        <div class="detail-value">${{data.id}}</div>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Status</span>
                        <div class="detail-value" style="color: ${{data.status === 'executed' ? '#00d4ff' : '#aaa'}}">${{data.status.toUpperCase()}}</div>
                    </div>
                `;
                
                if (details.duration) {{
                    html += `
                    <div class="detail-row">
                        <span class="detail-label">Duration</span>
                        <div class="detail-value">${{details.duration}}</div>
                    </div>`;
                }}
                
                if (details.error) {{
                    html += `
                    <div class="detail-row">
                        <span class="detail-label">Error</span>
                        <div class="detail-value" style="color: #ff4757">${{details.error}}</div>
                    </div>`;
                }}
                
                if (details.findings) {{
                    html += `
                    <div class="detail-row">
                        <span class="detail-label">Findings</span>
                        <div class="detail-value">
                            <span style="color: #ffa502; font-weight: bold;">${{details.findings}}</span>
                            <a href="#findings-section" style="float: right; color: #00d4ff; text-decoration: none; font-size: 0.8rem;">View Findings &darr;</a>
                        </div>
                    </div>`;
                }}

                if (details.variables) {{
                    html += `
                    <div class="detail-row" style="margin-top: 1rem; border-top: 1px solid #333; padding-top: 0.5rem;">
                        <span class="detail-label">Variables Captured</span>
                        <pre style="font-size: 0.8rem; margin-top: 5px;">${{details.variables}}</pre>
                    </div>`;
                }}

                if (details.output) {{
                    html += `
                    <div class="detail-row" style="margin-top: 1rem; border-top: 1px solid #333; padding-top: 0.5rem;">
                        <span class="detail-label">Step Output</span>
                        <pre style="font-size: 0.8rem; margin-top: 5px;">${{details.output}}</pre>
                    </div>`;
                }}

                detailsContent.innerHTML = html;
                cy.resize(); 
            }});
            
            cy.on('tap', function(evt){{
                if(evt.target === cy){{
                    detailsPanel.classList.add('hidden');
                }}
            }});
        }});
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
