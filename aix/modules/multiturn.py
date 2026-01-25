"""
AIX Multi-Turn Attack Module

Advanced multi-turn conversation attacks including:
- Crescendo attacks (gradual escalation)
- Trust building sequences
- Context poisoning
- Role lock exploitation
- Memory injection
- Instruction layering

These attacks exploit the stateful nature of conversations
to bypass safety measures that work well against single-shot attacks.
"""
import asyncio
import json
import os
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from aix.core.conversation import ConversationManager, ConversationStatus
from aix.core.reporter import Finding, Severity
from aix.core.scanner import BaseScanner, CircuitBreakerError, run_scanner
from aix.core.turn_evaluator import TurnEvaluator

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class MultiTurnScanner(BaseScanner):
    """
    Scanner for multi-turn conversation attacks.

    Executes attack sequences that span multiple conversation turns,
    exploiting context accumulation to bypass safety measures.
    """

    # Attack categories
    CATEGORIES = {
        "crescendo": "Gradual escalation from benign to malicious",
        "trust_building": "Establish rapport before payload delivery",
        "context_poisoning": "Inject context early, trigger later",
        "role_lock": "Deep persona establishment and exploitation",
        "memory_injection": "Poison conversation memory/history",
        "instruction_layering": "Stack partial instructions across turns",
        "cognitive_overload": "Overwhelm with complexity before attack",
        "authority_transfer": "Transfer perceived authority across turns",
    }

    def __init__(self, target: str, api_key: str | None = None, verbose: bool = False,
                 parsed_request: Optional['ParsedRequest'] = None, **kwargs):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "MULTI"
        self.console_color = "magenta"

        # Multi-turn specific config
        self.category = kwargs.get('category', 'all')
        self.max_turns = kwargs.get('max_turns', 10)
        self.turn_delay = kwargs.get('turn_delay', 0.5)

        # Load sequences
        self.sequences = self._load_sequences()

        # Setup evaluator
        self.turn_evaluator = TurnEvaluator(llm_judge=self.evaluator)

    def _load_sequences(self) -> list[dict]:
        """Load multi-turn attack sequences from JSON file."""
        payload_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'multiturn.json')

        try:
            with open(payload_path) as f:
                data = json.load(f)

            sequences = data.get("sequences", [])

            # Filter by level, risk, and category
            filtered = []
            for seq in sequences:
                # Level/risk filtering
                seq_level = seq.get("level", 1)
                seq_risk = seq.get("risk", 1)

                if seq_level > self.level or seq_risk > self.risk:
                    continue

                # Category filtering
                if self.category != "all":
                    if seq.get("category") != self.category:
                        continue

                # Turn count filtering
                if len(seq.get("turns", [])) > self.max_turns:
                    continue

                # Apply evasion to payloads if enabled
                if self.evasion_level != 'none':
                    for turn in seq.get("turns", []):
                        if "payload" in turn:
                            turn["original_payload"] = turn["payload"]
                            turn["payload"] = self.evasion.evade(turn["payload"])

                filtered.append(seq)

            self._print('info', f"Loaded {len(filtered)}/{len(sequences)} sequences (Level={self.level}, Risk={self.risk})")
            return filtered

        except FileNotFoundError:
            self._print('error', f"Sequences file not found: {payload_path}")
            return []
        except json.JSONDecodeError as e:
            self._print('error', f"Invalid JSON in sequences file: {e}")
            return []

    async def run(self, sequences: list[dict] = None):
        """
        Execute multi-turn attack sequences.

        Args:
            sequences: Optional list of sequences to run (defaults to loaded sequences)

        Returns:
            List of Finding objects
        """
        if sequences is None:
            sequences = self.sequences

        if not sequences:
            self._print('warning', "No sequences to execute")
            return self.findings

        self._print('info', f"Testing {len(sequences)} multi-turn sequences...")

        # Create connector
        connector = self._create_connector()
        await connector.connect()
        await self.gather_context(connector)

        # Create conversation manager
        conv_manager = ConversationManager(
            connector=connector,
            evaluator=self.turn_evaluator,
            verbose=self.verbose,
            delay=self.turn_delay
        )

        # Track stats by category
        category_stats = {}

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
                disable=not self.show_progress
            ) as progress:

                task = progress.add_task(
                    "[bold magenta]🔄 Multi-Turn Attacks...[/]",
                    total=len(sequences)
                )

                for seq in sequences:
                    self.stats['total'] += 1
                    seq_name = seq.get("name", "unnamed")
                    seq_category = seq.get("category", "unknown")

                    # Initialize category stats
                    if seq_category not in category_stats:
                        category_stats[seq_category] = {"total": 0, "success": 0}
                    category_stats[seq_category]["total"] += 1

                    try:
                        # Execute sequence
                        result = await conv_manager.execute_sequence(seq)

                        if result.success:
                            self.stats['success'] += 1
                            category_stats[seq_category]["success"] += 1

                            # Create finding
                            severity = Severity[seq.get("severity", "HIGH")]
                            finding = Finding(
                                title=f"Multi-Turn {seq_category.replace('_', ' ').title()} Attack",
                                severity=severity,
                                technique=seq_name,
                                payload=f"[{result.turns_executed} turns] {seq.get('description', '')}",
                                response=result.final_response[:2000],
                                target=self.target,
                                reason=f"Matched: {result.matched_indicators}",
                                owasp=seq.get('owasp', [])
                            )
                            self.findings.append(finding)

                            # Save to DB
                            self.db.add_result(
                                self.target,
                                'multiturn',
                                seq_name,
                                'success',
                                f"Sequence: {seq_name} ({result.turns_executed} turns)",
                                result.final_response[:2000],
                                severity.value,
                                reason=f"Category: {seq_category}, Indicators: {result.matched_indicators}",
                                owasp=seq.get('owasp', [])
                            )

                            self._print('success', f"[{result.turns_executed} turns]", seq_name,
                                       response=result.final_response)

                            # Show additional details if verbose
                            if self.verbose >= 1:
                                self._print('detail', f"Category: {seq_category}")
                                self._print('detail', f"Indicators matched: {result.matched_indicators}")
                                if result.variables_extracted:
                                    self._print('detail', f"Extracted: {list(result.variables_extracted.keys())}")

                        else:
                            self.stats['blocked'] += 1
                            self._print('blocked', f"[{result.turns_executed} turns] {result.status.value}", seq_name)

                    except CircuitBreakerError:
                        self._print('error', "Circuit breaker triggered - too many errors")
                        break

                    except Exception as e:
                        self.stats['blocked'] += 1
                        self._print('error', f"Error executing {seq_name}: {e}")

                    progress.update(task, advance=1)

                    # Small delay between sequences
                    await asyncio.sleep(0.3)

        finally:
            await connector.close()

        # Print summary
        self._print_summary(category_stats)

        return self.findings

    def _print_summary(self, category_stats: dict):
        """Print attack summary with category breakdown."""
        self.console.print()
        self._print('info', f"Summary: {self.stats['success']} successful, {self.stats['blocked']} blocked")

        if self.verbose >= 1 and category_stats:
            table = Table(title="Results by Category", show_header=True)
            table.add_column("Category", style="cyan")
            table.add_column("Success", style="green")
            table.add_column("Total", style="white")
            table.add_column("Rate", style="yellow")

            for cat, stats in sorted(category_stats.items()):
                rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
                table.add_row(
                    cat.replace("_", " ").title(),
                    str(stats["success"]),
                    str(stats["total"]),
                    f"{rate:.1f}%"
                )

            self.console.print(table)


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(MultiTurnScanner, target, api_key=api_key, **kwargs)
