"""
AIX Chain Executor - Attack chain execution engine

Handles:
- Sequential step execution
- Conditional branching
- Dynamic module invocation
- Timeout and error handling
- Result aggregation
"""
import asyncio
import importlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, TYPE_CHECKING

from rich.console import Console

from .context import ChainContext, StepResult, StepStatus
from .playbook import Playbook, StepConfig, StepType, StepAction
from aix.core.reporting.base import Finding, Severity

if TYPE_CHECKING:
    from aix.core.reporting.visualizer import LiveChainVisualizer

console = Console()


class ChainError(Exception):
    """Base exception for chain execution errors."""
    pass


class ChainTimeoutError(ChainError):
    """Chain execution timed out."""
    pass


class ChainAbortError(ChainError):
    """Chain was aborted (by config or critical finding)."""
    pass


@dataclass
class ChainResult:
    """Final result of chain execution."""
    playbook_name: str
    success: bool
    target: str
    started_at: datetime
    finished_at: datetime
    total_duration: float
    steps_executed: int
    steps_successful: int
    steps_failed: int
    execution_path: list[str]
    findings: list[Finding]
    context: ChainContext
    error: str | None = None
    aborted: bool = False
    abort_reason: str | None = None

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'playbook_name': self.playbook_name,
            'success': self.success,
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'finished_at': self.finished_at.isoformat(),
            'total_duration': self.total_duration,
            'steps_executed': self.steps_executed,
            'steps_successful': self.steps_successful,
            'steps_failed': self.steps_failed,
            'execution_path': self.execution_path,
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'error': self.error,
            'aborted': self.aborted,
            'abort_reason': self.abort_reason,
            'findings': [f.to_dict() for f in self.findings],
        }


class ChainExecutor:
    """
    Main execution engine for attack chains.

    Handles:
    - Step-by-step execution
    - Module invocation
    - Conditional branching
    - Variable interpolation
    - Timeout enforcement
    - Critical finding stops
    """

    # Module path mapping
    MODULE_MAP = {
        'recon': 'aix.modules.recon',
        'inject': 'aix.modules.inject',
        'jailbreak': 'aix.modules.jailbreak',
        'extract': 'aix.modules.extract',
        'leak': 'aix.modules.leak',
        'exfil': 'aix.modules.exfil',
        'memory': 'aix.modules.memory',
        'agent': 'aix.modules.agent',
        'dos': 'aix.modules.dos',
        'fuzz': 'aix.modules.fuzz',
        'fingerprint': 'aix.modules.fingerprint',
        'rag': 'aix.modules.rag',
        'multiturn': 'aix.modules.multiturn',
    }

    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: int = 0,
        visualizer: 'LiveChainVisualizer | None' = None,
        **extra_config
    ):
        """
        Initialize chain executor.

        Args:
            target: Target URL or endpoint
            api_key: API key for target
            verbose: Verbosity level (0=quiet, 1=normal, 2=debug)
            visualizer: Optional live visualizer for progress display
            console: Optional shared console instance
            **extra_config: Additional config passed to all modules
        """
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.visualizer = visualizer
        self.extra_config = extra_config
        self.console = extra_config.pop('console', None) or Console()

        # Execution state
        self._abort_requested = False
        self._abort_reason: str | None = None

    async def execute(self, playbook: Playbook, var_overrides: dict | None = None) -> ChainResult:
        """
        Execute a playbook.

        Args:
            playbook: Parsed Playbook to execute
            var_overrides: Optional variable overrides from CLI

        Returns:
            ChainResult with execution details
        """
        started_at = datetime.now()
        start_time = time.time()

        # Initialize context
        context = ChainContext(
            target=self.target,
            api_key=self.api_key,
            variables=playbook.variables.copy(),
            extra_config=self.extra_config,
            started_at=started_at,
        )

        # Apply variable overrides
        if var_overrides:
            context.variables.update(var_overrides)

        # Stats
        steps_executed = 0
        steps_successful = 0
        steps_failed = 0

        # Get first step
        current_step = playbook.get_first_step()

        if not current_step:
            return ChainResult(
                playbook_name=playbook.name,
                success=False,
                target=self.target,
                started_at=started_at,
                finished_at=datetime.now(),
                total_duration=0,
                steps_executed=0,
                steps_successful=0,
                steps_failed=0,
                execution_path=[],
                findings=[],
                context=context,
                error="Playbook has no steps",
            )

        # Notify visualizer
        if self.visualizer:
            self.visualizer.start(playbook)

        try:
            # Main execution loop
            while current_step and not self._abort_requested:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > playbook.config.max_duration:
                    self._abort_requested = True
                    self._abort_reason = f"Exceeded max duration ({playbook.config.max_duration}s)"
                    break

                context.current_step = current_step.id

                # Update visualizer
                if self.visualizer:
                    self.visualizer.update_step(current_step.id, StepStatus.RUNNING)

                # Check step pre-condition
                if current_step.condition:
                    if not context.evaluate_condition(current_step.condition):
                        if self.verbose >= 1:
                            self._print_step_skip(current_step, "condition not met")
                        if self.visualizer:
                            self.visualizer.update_step(current_step.id, StepStatus.SKIPPED)
                        current_step = self._get_next_step(playbook, current_step, True, context)
                        continue

                # Execute based on step type
                if current_step.type == StepType.MODULE:
                    result = await self._execute_module_step(current_step, context, playbook)
                elif current_step.type == StepType.CONDITION:
                    result = self._execute_condition_step(current_step, context)
                elif current_step.type == StepType.REPORT:
                    result = self._execute_report_step(current_step, context)
                else:
                    result = StepResult(
                        step_id=current_step.id,
                        status=StepStatus.SKIPPED,
                        success=True,
                    )

                # Record result
                context.add_result(result)
                steps_executed += 1

                if result.success:
                    steps_successful += 1
                    if self.visualizer:
                        self.visualizer.update_step(current_step.id, StepStatus.SUCCESS, result=result)
                else:
                    steps_failed += 1
                    if self.visualizer:
                        self.visualizer.update_step(current_step.id, StepStatus.FAILED, result=result)

                # Check for critical findings
                if playbook.config.stop_on_critical and result.has_critical:
                    self._abort_requested = True
                    self._abort_reason = "Critical finding detected"
                    if self.verbose >= 1:
                        self.console.print("[bold red][!] CRITICAL finding - stopping chain[/bold red]")
                    break

                # Determine next step
                current_step = self._get_next_step(playbook, current_step, result.success, context)

        except asyncio.TimeoutError:
            self._abort_reason = "Timeout"
        except ChainAbortError as e:
            self._abort_reason = str(e)
        except Exception as e:
            self._abort_reason = f"Error: {str(e)}"
            if self.verbose >= 2:
                import traceback
                traceback.print_exc()

        finished_at = datetime.now()
        total_duration = time.time() - start_time

        # Finalize visualizer
        if self.visualizer:
            self.visualizer.finish()

        return ChainResult(
            playbook_name=playbook.name,
            success=steps_failed == 0 and not self._abort_requested,
            target=self.target,
            started_at=started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            steps_executed=steps_executed,
            steps_successful=steps_successful,
            steps_failed=steps_failed,
            execution_path=context.execution_path,
            findings=context.all_findings,
            context=context,
            aborted=self._abort_requested,
            abort_reason=self._abort_reason,
        )

    async def _execute_module_step(
        self,
        step: StepConfig,
        context: ChainContext,
        playbook: Playbook
    ) -> StepResult:
        """Execute a MODULE type step."""
        step_start = time.time()
        started_at = datetime.now()

        if self.verbose >= 1:
            self._print_step_start(step)

        # Get module
        module_name = step.module
        if not module_name:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                success=False,
                error="No module specified",
                started_at=started_at,
                finished_at=datetime.now(),
            )

        module_path = self.MODULE_MAP.get(module_name)
        if not module_path:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                success=False,
                error=f"Unknown module: {module_name}",
                started_at=started_at,
                finished_at=datetime.now(),
            )

        # Import module
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                success=False,
                error=f"Failed to import module {module_name}: {e}",
                started_at=started_at,
                finished_at=datetime.now(),
            )

        # Get scanner class
        scanner_class = self._get_scanner_class(module, module_name)
        if not scanner_class:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                success=False,
                error=f"No scanner class found in {module_name}",
                started_at=started_at,
                finished_at=datetime.now(),
            )

        # Interpolate config
        step_config = context.interpolate_dict(step.config)

        # Merge with extra config
        # Quiet mode suppresses module output in chain mode (only show chain visualization)
        module_config = {
            **self.extra_config,
            **step_config,
            'verbose': self.verbose,
            'quiet': True,  # Suppress individual module output in chain mode
            'show_progress': True,  # Enable module progress bars in chain mode
            'console': self.console, # Use shared console to prevent UI artifacts
        }

        # Execute module
        try:
            scanner = scanner_class(
                self.target,
                api_key=self.api_key,
                **module_config
            )

            # Run with timeout
            findings = await asyncio.wait_for(
                scanner.run(),
                timeout=step.timeout
            )

            # Extract stored variables
            stored_vars = self._extract_stored_vars(step.store, findings, scanner, context)

            duration = time.time() - step_start
            success = len(findings) > 0 if findings else False

            if self.verbose >= 1:
                self._print_step_complete(step, success, len(findings) if findings else 0, duration)

            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS if success else StepStatus.FAILED,
                success=success or playbook.config.continue_on_module_fail,
                findings=findings or [],
                stored_vars=stored_vars,
                duration=duration,
                started_at=started_at,
                finished_at=datetime.now(),
            )

        except asyncio.TimeoutError:
            duration = time.time() - step_start
            if self.verbose >= 1:
                self.console.print(f"[yellow][!] Step '{step.id}' timed out after {step.timeout}s[/yellow]")
            return StepResult(
                step_id=step.id,
                status=StepStatus.TIMEOUT,
                success=False,
                error=f"Timeout after {step.timeout}s",
                duration=duration,
                started_at=started_at,
                finished_at=datetime.now(),
            )

        except Exception as e:
            duration = time.time() - step_start
            if self.verbose >= 1:
                self.console.print(f"[red][!] Step '{step.id}' failed: {e}[/red]")
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                success=False,
                error=str(e),
                duration=duration,
                started_at=started_at,
                finished_at=datetime.now(),
            )

    def _execute_condition_step(self, step: StepConfig, context: ChainContext) -> StepResult:
        """Execute a CONDITION type step."""
        started_at = datetime.now()

        if self.verbose >= 1:
            self.console.print(f"[dim]  ├─ Evaluating condition: {step.id}[/dim]")

        # Evaluate conditions
        next_step = None
        matched_condition = None

        if step.conditions:
            for cond in step.conditions:
                if 'if' in cond:
                    if context.evaluate_condition(cond['if']):
                        next_step = cond.get('then')
                        matched_condition = cond['if']
                        break
                elif 'else' in cond:
                    next_step = cond.get('else') or cond.get('then')
                    matched_condition = 'else'
                    break

        if self.verbose >= 1 and matched_condition:
            target = next_step or "continue"
            self.console.print(f"[dim]  │  └─ Matched: {matched_condition} → {target}[/dim]")

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            success=True,
            output={'next_step': next_step, 'matched': matched_condition},
            started_at=started_at,
            finished_at=datetime.now(),
        )

    def _execute_report_step(self, step: StepConfig, context: ChainContext) -> StepResult:
        """Execute a REPORT type step."""
        started_at = datetime.now()

        if self.verbose >= 1:
            self.console.print(f"[dim]  ├─ Generating report[/dim]")

        # Report generation will be handled by the CLI
        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            success=True,
            output={'format': step.config.get('format', 'html')},
            started_at=started_at,
            finished_at=datetime.now(),
        )

    def _get_next_step(
        self,
        playbook: Playbook,
        current: StepConfig,
        success: bool,
        context: ChainContext
    ) -> StepConfig | None:
        """Determine the next step based on current result."""
        # Check condition step output
        result = context.get_result(current.id)
        if result and current.type == StepType.CONDITION:
            next_id = result.output.get('next_step')
            if next_id:
                if next_id == 'abort':
                    self._abort_requested = True
                    self._abort_reason = "Condition led to abort"
                    return None
                return playbook.get_step(next_id)

        # Normal flow
        if success:
            next_id = current.on_success
        else:
            next_id = current.on_fail

        if not next_id:
            # No explicit next step - try sequential
            step_ids = playbook.get_step_ids()
            try:
                current_idx = step_ids.index(current.id)
                if current_idx + 1 < len(step_ids):
                    return playbook.steps[current_idx + 1]
            except ValueError:
                pass
            return None

        # Handle special actions
        if next_id == 'abort':
            self._abort_requested = True
            self._abort_reason = "Step led to abort"
            return None
        if next_id == 'continue':
            # Continue to next sequential step
            step_ids = playbook.get_step_ids()
            try:
                current_idx = step_ids.index(current.id)
                if current_idx + 1 < len(step_ids):
                    return playbook.steps[current_idx + 1]
            except ValueError:
                pass
            return None
        if next_id == 'report':
            # Find report step if exists
            for step in playbook.steps:
                if step.type == StepType.REPORT:
                    return step
            return None

        return playbook.get_step(next_id)

    def _get_scanner_class(self, module: Any, module_name: str) -> type | None:
        """Get the scanner class from a module."""
        # Common naming patterns
        class_names = [
            f"{module_name.title()}Scanner",
            f"{module_name.upper()}Scanner",
            f"{module_name.capitalize()}Scanner",
        ]

        for name in class_names:
            if hasattr(module, name):
                return getattr(module, name)

        # Fallback: find any class ending in Scanner
        for attr_name in dir(module):
            if attr_name.endswith('Scanner') and not attr_name.startswith('_'):
                attr = getattr(module, attr_name)
                if isinstance(attr, type):
                    return attr

        return None

    def _extract_stored_vars(
        self,
        store_config: dict,
        findings: list[Finding] | None,
        scanner: Any,
        context: ChainContext
    ) -> dict:
        """Extract variables to store from step results."""
        stored = {}

        if not store_config:
            return stored

        # Get scanner results dict if available (for recon module)
        scanner_results = getattr(scanner, 'results', {}) if scanner else {}

        for var_name, source_path in store_config.items():
            value = None

            # Parse source path
            if source_path.startswith('findings.'):
                field = source_path.replace('findings.', '')

                # Check scanner.results first for recon-specific fields
                if field == 'model_type' and scanner_results.get('model'):
                    value = scanner_results['model']
                elif field == 'has_rag':
                    # Check scanner results first
                    if 'rag' in str(scanner_results.get('capabilities', [])).lower():
                        value = True
                    elif findings:
                        for f in findings:
                            if hasattr(f, 'technique') and ('rag' in f.technique.lower() or 'retrieval' in getattr(f, 'response', '').lower()):
                                value = True
                                break
                    if value is None:
                        value = False
                elif field == 'has_tools':
                    # Check scanner results first
                    caps = scanner_results.get('capabilities', [])
                    if any('tool' in c.lower() or 'function' in c.lower() or 'code' in c.lower() for c in caps):
                        value = True
                    elif findings:
                        for f in findings:
                            if hasattr(f, 'technique') and ('tool' in f.technique.lower() or 'function' in getattr(f, 'response', '').lower()):
                                value = True
                                break
                    if value is None:
                        value = False
                elif findings:
                    if field == 'count':
                        value = len(findings)
                    elif field == 'any_success':
                        value = len(findings) > 0
                    elif field == 'first':
                        value = findings[0] if findings else None
                    elif field == 'extracted_prompt':
                        # Special case for extract module
                        for f in findings:
                            if hasattr(f, 'technique') and ('prompt' in f.technique.lower() or 'system' in f.technique.lower()):
                                value = getattr(f, 'response', None)
                                break
                else:
                    # No findings
                    if field in ('count', 'any_success'):
                        value = 0 if field == 'count' else False
                    elif field in ('has_rag', 'has_tools'):
                        value = False

            # Try scanner attributes
            elif hasattr(scanner, source_path):
                value = getattr(scanner, source_path)

            # Store if we got a value
            if value is not None:
                stored[var_name] = value

        return stored

    def _print_step_start(self, step: StepConfig) -> None:
        """Print step start message."""
        module = step.module or step.type.value
        self.console.print(f"[bold cyan]▶[/bold cyan] {step.name} [dim]({module})[/dim]")

    def _print_step_complete(self, step: StepConfig, success: bool, findings: int, duration: float) -> None:
        """Print step completion message."""
        status = "[green]✓[/green]" if success else "[red]✗[/red]"
        findings_str = f", {findings} findings" if findings > 0 else ""
        self.console.print(f"  {status} Completed in {duration:.1f}s{findings_str}")

    def _print_step_skip(self, step: StepConfig, reason: str) -> None:
        """Print step skip message."""
        self.console.print(f"[dim]  ○ Skipped: {step.name} ({reason})[/dim]")


def print_chain_summary(result: ChainResult, console: Console | None = None) -> None:
    """Print a summary of chain execution."""
    if console is None:
        console = Console()

    # Header
    status = "[green]SUCCESS[/green]" if result.success else "[red]FAILED[/red]"
    if result.aborted:
        status = f"[yellow]ABORTED[/yellow] ({result.abort_reason})"

    console.print()
    console.print(f"[bold]═══ Chain Summary ═══[/bold]")
    console.print(f"Playbook: {result.playbook_name}")
    console.print(f"Target: {result.target}")
    console.print(f"Status: {status}")
    console.print(f"Duration: {result.total_duration:.1f}s")
    console.print()

    # Steps
    console.print(f"[bold]Steps:[/bold] {result.steps_executed} executed, "
                  f"{result.steps_successful} successful, {result.steps_failed} failed")

    # Execution path
    if result.execution_path:
        path_str = " → ".join(result.execution_path)
        console.print(f"[dim]Path: {path_str}[/dim]")

    # Findings
    console.print()
    console.print(f"[bold]Findings:[/bold] {result.total_findings} total")
    if result.critical_count > 0:
        console.print(f"  [red]CRITICAL: {result.critical_count}[/red]")
    if result.high_count > 0:
        console.print(f"  [yellow]HIGH: {result.high_count}[/yellow]")

    console.print()
