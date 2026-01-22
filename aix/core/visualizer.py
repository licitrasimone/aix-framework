"""
AIX Chain Visualizer - Visualization for attack chain playbooks

Handles:
- Static ASCII flowchart visualization
- Live execution progress display
- Mermaid diagram export
- Dry-run execution plan display
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from aix.core.context import StepResult, StepStatus
from aix.core.playbook import Playbook, StepConfig, StepType
from aix.core.reporter import Severity


# Module color mapping
MODULE_COLORS = {
    'recon': 'cyan',
    'inject': 'magenta',
    'jailbreak': 'red',
    'extract': 'yellow',
    'leak': 'orange1',
    'exfil': 'red',
    'rag': 'green',
    'agent': 'blue',
    'multiturn': 'purple',
    'memory': 'bright_magenta',
    'dos': 'bright_red',
    'fuzz': 'bright_yellow',
    'fingerprint': 'bright_cyan',
    'condition': 'white',
    'report': 'bright_white',
}

# Status symbols
STATUS_SYMBOLS = {
    StepStatus.PENDING: '○',
    StepStatus.RUNNING: '●',
    StepStatus.SUCCESS: '✓',
    StepStatus.FAILED: '✗',
    StepStatus.SKIPPED: '◌',
    StepStatus.TIMEOUT: '⏱',
}

STATUS_COLORS = {
    StepStatus.PENDING: 'dim',
    StepStatus.RUNNING: 'cyan',
    StepStatus.SUCCESS: 'green',
    StepStatus.FAILED: 'red',
    StepStatus.SKIPPED: 'dim',
    StepStatus.TIMEOUT: 'yellow',
}


class PlaybookVisualizer:
    """Static visualization of playbook structure."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def render_tree(self, playbook: Playbook) -> Tree:
        """
        Render playbook as a Rich Tree.

        Args:
            playbook: Parsed playbook to visualize

        Returns:
            Rich Tree object
        """
        tree = Tree(
            f"[bold cyan]📋 {playbook.name}[/bold cyan]",
            guide_style="dim",
        )

        if playbook.description:
            tree.add(f"[dim]{playbook.description}[/dim]")

        # Variables
        if playbook.variables:
            var_branch = tree.add("[bold]Variables[/bold]")
            for name, value in playbook.variables.items():
                var_branch.add(f"[cyan]{name}[/cyan] = [yellow]{value}[/yellow]")

        # Steps
        steps_branch = tree.add("[bold]Steps[/bold]")
        for step in playbook.steps:
            step_node = self._render_step_node(step)
            steps_branch.add(step_node)

        return tree

    def _render_step_node(self, step: StepConfig) -> str:
        """Render a single step as a tree node."""
        color = MODULE_COLORS.get(step.module or step.type.value, 'white')

        # Icon based on type
        if step.type == StepType.MODULE:
            icon = '🔧'
        elif step.type == StepType.CONDITION:
            icon = '🔀'
        elif step.type == StepType.REPORT:
            icon = '📊'
        else:
            icon = '○'

        # Build node text
        node = f"{icon} [{color}]{step.id}[/{color}]"

        if step.module:
            node += f" [dim]({step.module})[/dim]"

        if step.on_success:
            node += f" [green]→ {step.on_success}[/green]"
        if step.on_fail:
            node += f" [red]✗→ {step.on_fail}[/red]"

        return node

    def render_ascii_graph(self, playbook: Playbook) -> str:
        """
        Render playbook as ASCII flowchart.

        Args:
            playbook: Parsed playbook to visualize

        Returns:
            ASCII art string
        """
        lines = []

        # Header
        lines.append("┌" + "─" * 60 + "┐")
        lines.append(f"│  PLAYBOOK: {playbook.name[:48]:<48}  │")
        lines.append("└" + "─" * 60 + "┘")
        lines.append("")

        # Build graph
        visited = set()
        step = playbook.get_first_step()

        while step and step.id not in visited:
            visited.add(step.id)

            # Step box
            step_type = step.type.value.upper()[:10]
            box = self._render_step_box(step)
            lines.extend(box)

            # Connections
            if step.on_success or step.on_fail:
                if step.type == StepType.CONDITION and step.conditions:
                    # Multiple branches
                    lines.append("       │")
                    branches = []
                    for cond in step.conditions:
                        target = cond.get('then') or cond.get('else')
                        if target:
                            branches.append(target)
                    if branches:
                        lines.append("   ┌───┼───┐")
                        lines.append("   ▼   ▼   ▼")
                else:
                    # Single connection
                    lines.append("       │")
                    lines.append("       ▼")

            # Next step
            if step.on_success and step.on_success not in ('abort', 'continue', 'report'):
                step = playbook.get_step(step.on_success)
            else:
                # Try sequential
                step_ids = playbook.get_step_ids()
                try:
                    idx = step_ids.index(step.id)
                    if idx + 1 < len(step_ids):
                        step = playbook.steps[idx + 1]
                    else:
                        step = None
                except ValueError:
                    step = None

        lines.append("")
        lines.append("Legend: [MODULE] Attack module  [CONDITION] Branch point  [REPORT] Output")

        return "\n".join(lines)

    def _render_step_box(self, step: StepConfig) -> list[str]:
        """Render a step as an ASCII box."""
        step_type = step.type.value.upper()[:10]
        id_line = step.id[:12].center(14)
        type_line = f"[{step_type}]".center(14)

        return [
            "    ┌" + "─" * 14 + "┐",
            f"    │{id_line}│",
            f"    │{type_line}│",
            "    └" + "─" * 14 + "┘",
        ]

    def print_static(self, playbook: Playbook) -> None:
        """Print static visualization of playbook."""
        # Print tree view
        tree = self.render_tree(playbook)
        self.console.print(tree)


class DryRunVisualizer:
    """Visualization for dry-run mode (execution plan without running)."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def render(self, playbook: Playbook, variables: dict | None = None) -> None:
        """
        Render dry-run execution plan.

        Args:
            playbook: Parsed playbook
            variables: Variable overrides
        """
        # Header
        self.console.print()
        self.console.print(Panel(
            f"[bold]DRY RUN: {playbook.name}[/bold]\n"
            "[dim]This shows the execution plan without running any attacks[/dim]",
            border_style="yellow",
        ))

        # Variables
        merged_vars = playbook.variables.copy()
        if variables:
            merged_vars.update(variables)

        if merged_vars:
            self.console.print()
            self.console.print("[bold]Variables (with defaults):[/bold]")
            for name, value in merged_vars.items():
                self.console.print(f"  [cyan]{name}[/cyan] = [yellow]{value}[/yellow]")

        # Execution plan
        self.console.print()
        self.console.print("[bold]Execution Plan:[/bold]")
        self.console.print("═" * 40)

        for i, step in enumerate(playbook.steps, 1):
            self._print_step_plan(i, step)

        # Possible paths
        self.console.print()
        self.console.print("[bold]Possible Paths:[/bold]")
        paths = self._analyze_paths(playbook)
        for path_name, path_steps in paths.items():
            self.console.print(f"  [dim]{path_name}:[/dim] {' → '.join(path_steps)}")

        self.console.print()

    def _print_step_plan(self, num: int, step: StepConfig) -> None:
        """Print a single step in the plan."""
        color = MODULE_COLORS.get(step.module or step.type.value, 'white')
        step_type = step.type.value

        self.console.print(f"\n[bold]{num}. {step.name}[/bold] [dim]({step_type})[/dim]")

        if step.module:
            self.console.print(f"   └─ Module: [{color}]{step.module}[/{color}]")

        if step.config:
            config_str = ", ".join(f"{k}={v}" for k, v in step.config.items())
            self.console.print(f"   └─ Config: [dim]{config_str}[/dim]")

        if step.store:
            store_str = ", ".join(step.store.keys())
            self.console.print(f"   └─ Stores: [cyan]{store_str}[/cyan]")

        if step.condition:
            self.console.print(f"   └─ Condition: [yellow]{step.condition}[/yellow]")

        if step.conditions:
            self.console.print("   └─ Branches:")
            for cond in step.conditions:
                if 'if' in cond:
                    target = cond.get('then', 'continue')
                    self.console.print(f"      ├─ IF {cond['if']} → {target}")
                elif 'else' in cond:
                    target = cond.get('else') or cond.get('then', 'continue')
                    self.console.print(f"      └─ ELSE → {target}")

        if step.on_success:
            self.console.print(f"   └─ On success → [green]{step.on_success}[/green]")
        if step.on_fail:
            self.console.print(f"   └─ On fail → [red]{step.on_fail}[/red]")

    def _analyze_paths(self, playbook: Playbook) -> dict[str, list[str]]:
        """Analyze possible execution paths."""
        paths = {}

        # Simple linear path
        linear = [s.id for s in playbook.steps if s.type == StepType.MODULE]
        if linear:
            paths["Linear"] = linear[:5] + (["..."] if len(linear) > 5 else [])

        # Find abort path
        for step in playbook.steps:
            if step.on_fail == 'abort':
                paths["Abort on fail"] = [step.id, "ABORT"]
                break

        return paths


class LiveChainVisualizer:
    """
    Real-time visualization during chain execution.

    Uses Rich Live for dynamic updates showing:
    - Current step status
    - Progress through chain
    - Findings count
    - Context variables
    """

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.playbook: Playbook | None = None
        self.live: Live | None = None

        # State
        self.step_status: dict[str, StepStatus] = {}
        self.step_times: dict[str, float] = {}
        self.step_results: dict[str, StepResult] = {}
        self.current_step: str | None = None
        self.start_time: float = 0
        self.findings_count = 0
        self.critical_count = 0
        self.high_count = 0
        self.variables: dict[str, Any] = {}

    def start(self, playbook: Playbook) -> None:
        """Start live visualization."""
        self.playbook = playbook
        self.start_time = time.time()

        # Initialize step status
        for step in playbook.steps:
            self.step_status[step.id] = StepStatus.PENDING

        # Start live display
        self.live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            transient=True,
        )
        self.live.start()

    def update_step(self, step_id: str, status: StepStatus, result: StepResult | None = None) -> None:
        """Update a step's status."""
        self.step_status[step_id] = status
        self.current_step = step_id if status == StepStatus.RUNNING else self.current_step

        if result:
            self.step_results[step_id] = result
            self.step_times[step_id] = result.duration

            # Update findings counts
            self.findings_count += len(result.findings)
            self.critical_count += result.critical_count
            self.high_count += result.high_count

            # Update variables
            self.variables.update(result.stored_vars)

        if self.live:
            self.live.update(self._render())

    def set_variable(self, name: str, value: Any) -> None:
        """Update a context variable."""
        self.variables[name] = value
        if self.live:
            self.live.update(self._render())

    def finish(self) -> None:
        """Stop live visualization."""
        if self.live:
            self.live.stop()
            self.live = None

    def _render(self) -> Panel:
        """Render current state as Rich Panel."""
        if not self.playbook:
            return Panel("No playbook loaded")

        elapsed = time.time() - self.start_time

        # Build content
        content_parts = []

        # Header info
        header = Text()
        header.append(f"Target: {self.playbook.name}\n", style="bold")
        header.append(f"Elapsed: {elapsed:.1f}s    ", style="dim")
        header.append(f"Findings: {self.findings_count}", style="bold")
        if self.critical_count > 0:
            header.append(f" ({self.critical_count} CRIT)", style="red bold")
        if self.high_count > 0:
            header.append(f" ({self.high_count} HIGH)", style="yellow")
        content_parts.append(header)
        content_parts.append(Text(""))

        # Steps
        for step in self.playbook.steps:
            step_line = self._render_step_line(step)
            content_parts.append(step_line)

        # Variables
        if self.variables:
            content_parts.append(Text(""))
            content_parts.append(Text("Context Variables:", style="bold"))
            for name, value in list(self.variables.items())[:5]:
                val_str = str(value)[:50]
                content_parts.append(Text(f"  {name}: {val_str}", style="dim"))

        return Panel(
            Group(*content_parts),
            title="[bold cyan]Chain Execution[/bold cyan]",
            border_style="cyan",
        )

    def _render_step_line(self, step: StepConfig) -> Text:
        """Render a single step line."""
        status = self.step_status.get(step.id, StepStatus.PENDING)
        symbol = STATUS_SYMBOLS.get(status, '?')
        color = STATUS_COLORS.get(status, 'white')

        line = Text()
        line.append(f"  [{symbol}] ", style=color)
        line.append(step.id, style="bold" if status == StepStatus.RUNNING else None)

        # Add time if completed
        if step.id in self.step_times:
            line.append(f" ({self.step_times[step.id]:.1f}s)", style="dim")

        # Add result info
        if step.id in self.step_results:
            result = self.step_results[step.id]
            if result.findings:
                line.append(f" [{len(result.findings)} findings]", style="green")
            if result.stored_vars:
                vars_str = ", ".join(result.stored_vars.keys())
                line.append(f" → {vars_str}", style="cyan")

        return line


class MermaidExporter:
    """Export playbook as Mermaid diagram."""

    def __init__(self, theme: str = 'default', direction: str = 'TD', icons: bool = True):
        """
        Initialize exporter.

        Args:
            theme: Mermaid theme (default, dark, forest, neutral)
            direction: Flow direction (TD, LR, BT, RL)
            icons: Include emoji icons in nodes
        """
        self.theme = theme
        self.direction = direction
        self.icons = icons

    def export(self, playbook: Playbook) -> str:
        """
        Export playbook as Mermaid diagram.

        Args:
            playbook: Parsed playbook

        Returns:
            Mermaid diagram syntax
        """
        lines = []

        # Header
        lines.append(f"flowchart {self.direction}")

        # Subgraph for playbook
        lines.append(f"    subgraph {self._sanitize(playbook.name)}")

        # Nodes
        for step in playbook.steps:
            node = self._render_node(step)
            lines.append(f"        {node}")

        lines.append("    end")
        lines.append("")

        # Edges
        for step in playbook.steps:
            edges = self._render_edges(step)
            for edge in edges:
                lines.append(f"    {edge}")

        # Styling
        lines.append("")
        lines.extend(self._render_styles(playbook))

        return "\n".join(lines)

    def _render_node(self, step: StepConfig) -> str:
        """Render a node definition."""
        icon = self._get_icon(step) if self.icons else ""
        label = f"{icon} {step.id}"

        if step.name and step.name != step.id:
            label += f"<br/>{step.name}"

        # Node shape based on type
        if step.type == StepType.CONDITION:
            return f'{step.id}{{"{label}"}}'
        elif step.type == StepType.REPORT:
            return f'{step.id}(["{label}"])'
        else:
            return f'{step.id}["{label}"]'

    def _render_edges(self, step: StepConfig) -> list[str]:
        """Render edges from a step."""
        edges = []

        if step.type == StepType.CONDITION and step.conditions:
            for cond in step.conditions:
                target = cond.get('then') or cond.get('else')
                if target and target not in ('abort', 'continue', 'report'):
                    label = cond.get('if', 'else')[:20]
                    edges.append(f'{step.id} -->|{label}| {target}')
        else:
            if step.on_success and step.on_success not in ('abort', 'continue', 'report'):
                edges.append(f'{step.id} -->|success| {step.on_success}')
            if step.on_fail and step.on_fail not in ('abort', 'continue', 'report'):
                edges.append(f'{step.id} -->|fail| {step.on_fail}')

        return edges

    def _render_styles(self, playbook: Playbook) -> list[str]:
        """Render style definitions."""
        styles = []

        color_map = {
            'recon': '#0891b2',
            'inject': '#a855f7',
            'jailbreak': '#dc2626',
            'extract': '#eab308',
            'leak': '#f97316',
            'exfil': '#ef4444',
            'rag': '#059669',
            'agent': '#3b82f6',
            'multiturn': '#8b5cf6',
            'condition': '#6366f1',
            'report': '#8b5cf6',
        }

        for step in playbook.steps:
            module = step.module or step.type.value
            color = color_map.get(module, '#64748b')
            styles.append(f"    style {step.id} fill:{color}")

        return styles

    def _get_icon(self, step: StepConfig) -> str:
        """Get emoji icon for step type."""
        icons = {
            'recon': '🔍',
            'inject': '💉',
            'jailbreak': '🔓',
            'extract': '📜',
            'leak': '💧',
            'exfil': '📤',
            'rag': '🗄️',
            'agent': '🤖',
            'multiturn': '💬',
            'memory': '🧠',
            'dos': '💥',
            'fuzz': '🔀',
            'fingerprint': '🔎',
            'condition': '🔀',
            'report': '📊',
        }
        module = step.module or step.type.value
        return icons.get(module, '○')

    def _sanitize(self, text: str) -> str:
        """Sanitize text for Mermaid."""
        return text.replace('"', "'").replace('\n', ' ')


def print_execution_summary(
    playbook: Playbook,
    execution_path: list[str],
    step_results: dict[str, StepResult],
    console: Console | None = None
) -> None:
    """
    Print execution summary with visual flow.

    Args:
        playbook: Executed playbook
        execution_path: List of executed step IDs
        step_results: Results keyed by step ID
        console: Rich console instance
    """
    if console is None:
        console = Console()

    console.print()
    console.print(f"[bold]═══ Execution Flow ═══[/bold]")
    console.print()

    for i, step_id in enumerate(execution_path):
        result = step_results.get(step_id)
        step = playbook.get_step(step_id)

        if not step:
            continue

        # Status symbol
        status = result.status if result else StepStatus.PENDING
        symbol = STATUS_SYMBOLS.get(status, '?')
        color = STATUS_COLORS.get(status, 'white')

        # Build line
        prefix = "├─▶" if i < len(execution_path) - 1 else "└─▶"
        console.print(f"[{color}]{prefix} {symbol} {step_id}[/{color}]")

        if result:
            # Duration
            if result.duration:
                console.print(f"│   [dim]Duration: {result.duration:.1f}s[/dim]")

            # Findings
            if result.findings:
                console.print(f"│   [green]Findings: {len(result.findings)}[/green]")

            # Stored vars
            if result.stored_vars:
                for var, val in result.stored_vars.items():
                    val_str = str(val)[:40]
                    console.print(f"│   [cyan]{var}[/cyan] = {val_str}")

            # Next step
            if i < len(execution_path) - 1:
                next_step = execution_path[i + 1]
                console.print(f"│   [dim]→ {next_step}[/dim]")

        console.print("│")

    console.print()
