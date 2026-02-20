"""
Base Scanner Module - Common logic for all AIX scanners
"""

import asyncio
import json
import os
import uuid
from abc import ABC
from typing import Any, Optional

from rich.console import Console

from aix.core.ai_engine import AIEngine
from aix.core.connector import APIConnector, RequestConnector, WebSocketConnector
from aix.core.context import TargetContext
from aix.core.evaluator import LLMEvaluator
from aix.core.evasion import PayloadEvasion
from aix.core.owasp import get_owasp_for_module, parse_owasp_list
from aix.core.reporting.base import Severity
from aix.core.request_parser import ParsedRequest
from aix.db.database import AIXDatabase


class CircuitBreakerError(Exception):
    """Raised when scan should be aborted due to excessive errors"""

    pass


class BaseScanner(ABC):
    """Base class for all AIX scanners to reduce code duplication"""

    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        timeout: int = 30,
        browser: bool = False,
        console: Console | None = None,
        **kwargs,
    ):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.parsed_request = parsed_request
        self.timeout = timeout  # Set from parameter
        self.browser = browser
        self.show_response = kwargs.get("show_response", False)
        # Always show progress unless explicitly disabled (default True)
        self.show_progress = kwargs.get("show_progress", True)

        # Quiet mode suppresses text output but keeps progress bars (used in chain mode)
        self.quiet = kwargs.get("quiet", False)
        self.console = console if console else Console()

        # Common optional arguments
        self.proxy = kwargs.get("proxy")
        self.cookies = kwargs.get("cookies")
        self.headers = kwargs.get("headers")
        self.injection_param = kwargs.get("injection_param")
        self.body_format = kwargs.get("body_format")
        self.refresh_config = kwargs.get("refresh_config")
        self.response_regex = kwargs.get("response_regex")
        self.response_path = kwargs.get("response_path")

        # Chat ID config
        self.chat_id_path = kwargs.get("chat_id_path")
        self.chat_id_param = kwargs.get("chat_id_param")
        self.new_chat = kwargs.get("new_chat", True)  # Default: fresh per payload

        # Session config
        self.session_id = kwargs.get("session_id")

        # Filtering config
        self.level = kwargs.get("level", 1)
        self.risk = kwargs.get("risk", 1)
        self.verify_attempts = kwargs.get("verify_attempts", 1)

        # Evasion config
        self.evasion_level = kwargs.get("evasion", "none")
        self.evasion = PayloadEvasion(self.evasion_level)

        self.timeout = kwargs.get("timeout", 30)

        # State
        self.findings = []
        self.stats = {"total": 0, "success": 0, "blocked": 0}
        self.db = AIXDatabase()
        self.payloads = []

        # Circuit Breaker State
        self.consecutive_errors = 0
        self.circuit_breaker_limit = 10

        # AI Engine (unified evaluator + context)
        self.ai_config = kwargs.get("ai_config")
        self.ai_engine: AIEngine | None = None
        self.context: TargetContext | None = None
        self.generate_count = kwargs.get("generate", 0)  # Number of payloads to generate

        if self.ai_config and self.ai_config.get("provider"):
            # Inject proxy into config if set
            if self.proxy:
                self.ai_config["proxy"] = self.proxy

            self.ai_engine = AIEngine(**self.ai_config)
            if not self.quiet:
                features = []
                if self.ai_config.get("enable_eval", True):
                    features.append("Eval")
                if self.ai_config.get("enable_context", True):
                    features.append("Context")
                self.console.print(
                    f"[bold green][*] AI Engine ENABLED: {self.ai_config.get('provider')} ({', '.join(features)})[/bold green]"
                )

        # Legacy evaluator support (backward compatibility)
        self.eval_config = kwargs.get("eval_config")
        self.evaluator = None
        if (
            not self.ai_engine
            and self.eval_config
            and (self.eval_config.get("url") or self.eval_config.get("provider"))
        ):
            # Inject proxy into eval config if set
            if self.proxy:
                self.eval_config["proxy"] = self.proxy

            self.evaluator = LLMEvaluator(**self.eval_config)
            if not self.quiet:
                self.console.print(
                    f"[bold green][*] LLM-as-a-Judge ENABLED: {self.eval_config.get('provider') or 'custom'} ({self.eval_config.get('model') or 'default'})[/bold green]"
                )

        # Module specific config (default, can be overridden)
        self.module_name = "BASE"
        self.db_module_name = None  # Override to use a different key in db.add_result()
        self.console_color = "white"

        self.last_eval_reason = None
        # Load refusals but disable them if LLM judge is active (user preference: LLM > refusals)
        self.refusals = (
            self.load_payloads("refusals.json", quiet=True) if not self.evaluator else []
        )

    def _update_error_state(self, error_str: str | None = None):
        """Update consecutive error count and check circuit breaker"""
        if error_str and ("403" in error_str or "500" in error_str):
            self.consecutive_errors += 1
        else:
            self.consecutive_errors = 0  # Reset on success or non-critical error

        if self.consecutive_errors >= self.circuit_breaker_limit:
            msg = f"Scan aborted: Exceeded {self.circuit_breaker_limit} consecutive critical errors (WAF block prevented?)"
            self._print("error", msg)
            raise CircuitBreakerError(msg)

    def load_payloads(self, filename: str, quiet: bool = False) -> list[dict]:
        """Load payloads from JSON file in ../payloads directory with filtering"""
        payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", filename)
        # self.console.print(f"[debug] Loading {filename} from {payload_path}")
        try:
            with open(payload_path) as f:
                payloads = json.load(f)
                # self.console.print(f"[debug] Parsed JSON for {filename}: {len(payloads)} items")

            filtered_payloads = []
            for p in payloads:
                # Default values if missing

                if isinstance(p, str):
                    # Handle simple string lists (like refusals.json)
                    filtered_payloads.append(p)
                    continue

                # Default values if missing
                curr_level = p.get("level", 1)
                curr_risk = p.get("risk", 1)

                # Filter logic: include if payload level/risk <= user requested level/risk
                if curr_level <= self.level and curr_risk <= self.risk:
                    # Reconstruct Severity objects
                    if isinstance(p.get("severity"), str):
                        try:
                            p["severity"] = Severity[p["severity"]]
                        except KeyError:
                            p["severity"] = Severity.MEDIUM

                    # Parse OWASP categories
                    if "owasp" in p and isinstance(p["owasp"], list):
                        p["owasp"] = parse_owasp_list(p["owasp"])
                    else:
                        # Default from module mapping
                        p["owasp"] = get_owasp_for_module(self.module_name.lower())

                    filtered_payloads.append(p)

            # Apply evasion to payloads if enabled
            if self.evasion_level != "none":
                for p in filtered_payloads:
                    if isinstance(p, dict) and "payload" in p:
                        p["original_payload"] = p["payload"]  # Keep original for logging
                        p["payload"] = self.evasion.evade(p["payload"])

            if not quiet:
                evasion_str = (
                    f", Evasion={self.evasion_level}" if self.evasion_level != "none" else ""
                )
                self._print(
                    "info",
                    f"Config: Level={self.level}, Risk={self.risk}{evasion_str} - Loaded {len(filtered_payloads)}/{len(payloads)} payloads",
                )
            return filtered_payloads
        except Exception as e:
            if not self.quiet:
                self.console.print(
                    f"[yellow][!] Could not load payloads from {payload_path}: {e}[/yellow]"
                )
            return []

    def _init_stats(self, **kwargs):
        """Update stats dictionary with default values"""
        self.stats.update(kwargs)

    def _create_connector(self):
        """Create the appropriate connector based on configuration"""
        if self.parsed_request:
            return RequestConnector(
                self.parsed_request,
                proxy=self.proxy,
                verbose=self.verbose,
                cookies=self.cookies,
                headers=self.headers,
                timeout=self.timeout,
                refresh_config=self.refresh_config,
                response_regex=self.response_regex,
                response_path=self.response_path,
                console=self.console,
                chat_id_path=self.chat_id_path,
                chat_id_param=self.chat_id_param,
            )
        elif self.target.startswith(("ws://", "wss://")):
            return WebSocketConnector(
                self.target,
                injection_param=self.injection_param,
                response_path=self.response_path,
                response_regex=self.response_regex,
                cookies=self.cookies,
                headers=self.headers,
                timeout=self.timeout,
                verbose=self.verbose,
                console=self.console,
                proxy=self.proxy,
                chat_id_path=self.chat_id_path,
                chat_id_param=self.chat_id_param,
            )
        else:
            return APIConnector(
                self.target,
                api_key=self.api_key,
                proxy=self.proxy,
                verbose=self.verbose,
                cookies=self.cookies,
                headers=self.headers,
                injection_param=self.injection_param,
                body_format=self.body_format,
                timeout=self.timeout,
                refresh_config=self.refresh_config,
                response_regex=self.response_regex,
                response_path=self.response_path,
                console=self.console,
                chat_id_path=self.chat_id_path,
                chat_id_param=self.chat_id_param,
            )

    def _print(self, status: str, msg: str, tech: str = "", response: str = None):
        """Standardized formatted printing"""
        # In quiet mode (chain execution), suppress text output but keep progress bars
        if self.quiet:
            return

        t = self.target[:28] + "..." if len(self.target) > 30 else self.target
        name = self.module_name[:7].upper()  # Limit length

        # Append evaluator reason if available and relevant
        # Only append for verdicts to avoid polluting detailed logs
        # Logic:
        # Level 0 (default): No reasons
        # Level 1 (-v): Show reasons
        # Level 2 (-vv): Show reasons + blocked

        should_show_reason = self.verbose >= 1

        if (
            should_show_reason
            and self.last_eval_reason
            and status in ["success", "blocked", "warning"]
        ):
            if msg:
                msg += f" - {self.last_eval_reason}"
            else:
                msg = f"Evaluator: {self.last_eval_reason}"

        if status == "info":
            self.console.print(
                f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [{self.console_color}][*][/{self.console_color}] {msg}"
            )
        elif status == "success":
            # Fixed: Include msg/reason in success output
            reason_str = f" [dim]({msg})[/dim]" if msg else ""
            self.console.print(
                f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [green][+][/green] {tech} [bold green](Vulnerable!)[/bold green]{reason_str}"
            )
            if self.show_response and response:
                escaped_response = response[:500].replace("[", r"\[")
                self.console.print(f"        [dim]Response: {escaped_response}[/dim]")
        elif status == "detail":
            # Details are shown if verbose >= 1 ? Usually details are useful.
            # But "only vulnerable" implies hiding details too?
            # User didn't specify details. Let's keep details if verbose >= 1 to match "vulnerable + evaluation" (evaluation is detail?)
            # Actually, `msg` contains the eval reason now.
            # The 'detail' status is used for things like "Category: ..." in agent.py.
            # Let's show details only if verbose >= 1.
            if self.verbose >= 1:
                self.console.print(
                    f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30}        [dim]└─→ {msg}[/dim]"
                )
        elif status == "warning":
            self.console.print(
                f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [yellow][!][/yellow] {msg}"
            )
        elif status == "blocked":
            # Show blocked only if verbose >= 2
            if self.verbose >= 2:
                reason_str = f" [dim]({msg})[/dim]" if msg else ""
                self.console.print(
                    f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][-][/red] {tech} [red](Blocked)[/red]{reason_str}"
                )
        elif status == "error":
            self.console.print(
                f"[{self.console_color}]{name:<7}[/{self.console_color}] {t:30} [red][!][/red] {msg}"
            )

    async def _check_refusal(self, response: str) -> bool:
        """Check if response contains refusal patterns"""
        response_lower = response.lower()
        # self.console.print(f"[debug] Checking refusal for: {response_lower[:50]}...")
        # self.console.print(f"[debug] Against {len(self.refusals)} patterns: {self.refusals}")
        for r in self.refusals:
            # refusals.json is a list of strings
            if isinstance(r, str) and r.lower() in response_lower:
                # self.console.print(f"[debug] MATCHED REFUSAL: {r}")
                return True
        return False

    async def check_success(
        self, response: str, indicators: list[str], payload: str, technique: str
    ) -> bool:
        """
        Check if the attack was successful.
        Uses AI Engine or LLM Evaluator if available, otherwise falls back to string matching.
        """
        # Reset reason
        self.last_eval_reason = None

        # 1. Use AI Engine if available (new unified system)
        if self.ai_engine and self.ai_engine.enable_eval:
            result = await self.ai_engine.evaluate(response, payload, technique)
            self.last_eval_reason = result.get("reason")
            return result.get("vulnerable", False)

        # 2. Use legacy Evaluator if available
        if self.evaluator:
            result = await self.evaluator.evaluate(response, payload, technique)
            self.last_eval_reason = result.get("reason")
            if result.get("vulnerable"):
                return True
            else:
                return False

        # 3. Fallback to keywords
        success = any(i.lower() in response.lower() for i in indicators)

        # Check for refusals if no evaluator is used
        if success and await self._check_refusal(response):
            self.last_eval_reason = "Blocked by refusal check (False Positive)"
            # Treat as blocked/safe if it's a known refusal, unless indicators are very specific?
            # User requested to avoid opening vuln for 'i cannot provide'.
            # So we flip success to False.
            return False

        if success:
            self.last_eval_reason = "Matched indicator found in response."
        return success

    async def verify_result(
        self, response: str, connector, payload: str, indicators: list[str], technique: str
    ) -> bool:
        """
        [DEPRECATED] Use scan_payload instead.
        Keep for backward compatibility during refactor.
        """
        return await self.check_success(response, indicators, payload, technique)

    async def scan_payload(
        self, connector, payload: str, indicators: list[str], technique: str
    ) -> tuple[bool, str]:
        """
        Robust payload scanning.
        Sends payload `verify_attempts` times.
        Returns: (is_vulnerable, best_response)

        Logic:
        - If verify_attempts > 1:
            - Try N times.
            - If ANY attempt succeeds -> Vulnerable.
            - If ALL fail -> Blocked.
            - Calculate success rate.
        - If verify_attempts == 1:
            - Try once.
        """
        attempts = self.verify_attempts
        successes = 0
        failures = 0
        best_response = None
        best_reason = None  # Store reason from successful attempt

        # If default 1 attempt, use fast path
        if attempts <= 1:
            resp = await connector.send(payload)
            success = await self.check_success(resp, indicators, payload, technique)
            return success, resp

        # Robust loop
        if self.verbose >= 2:
            self._print("info", f"Probing {technique} ({attempts} attempts)...")

        for i in range(attempts):
            try:
                resp = await connector.send(payload)
                if not resp:
                    resp = ""  # Handle empty

                success = await self.check_success(resp, indicators, payload, technique)

                if success:
                    successes += 1
                    best_response = resp  # Prefer successful response
                    # Save the reason from successful attempt (don't let failures overwrite it)
                    if not best_reason:
                        best_reason = self.last_eval_reason
                    # Optimization: If user didn't ask for full rigorous stats, maybe stop?
                    # User said "sent always n attempts". So we continue.
                else:
                    failures += 1
                    if not best_response:
                        best_response = resp  # Keep at least one response (even failure)

            except Exception as e:
                failures += 1
                if not best_response:
                    best_response = f"Error: {e!s}"

                # Check for critical errors (403, etc.)
                error_str = str(e)
                if "403" in error_str:
                    self._print("error", f"Target returned 403 Forbidden ({technique})")
                    self._update_error_state(error_str)
                elif "500" in error_str:
                    self._print("error", f"Target returned 500 Server Error ({technique})")
                    self._update_error_state(error_str)
                elif self.verbose >= 1 and not self.quiet:  # Print other errors if verbose
                    self.console.print(f"[yellow][!] Error probing {technique}: {e}[/yellow]")
                    self._update_error_state(None)  # Reset if generic error? Or ignore?
                    # Let's reset for generic errors to be safe, or only pure successes?
                    # Ideally 403 is the blocker. If we get a connection error, maybe we shouldn't reset.
                    # But for now, let's only increment on 403/500 as per logic.
                    # Calling with None resets.
                    pass

        # Decision Logic
        if successes > 0:
            self._update_error_state(None)  # Reset count on any success
            # Restore the reason from a successful attempt
            if best_reason:
                self.last_eval_reason = best_reason
            if successes < attempts:
                self._print(
                    "warning", f"{technique}: Unstable exploit ({successes}/{attempts} successes)"
                )
            else:
                self._print("info", f"{technique}: robust ({successes}/{attempts} successes)")
            return True, best_response
        else:
            return False, best_response

    # ------------------------------------------------------------------
    # Template method helpers – subclasses can override the hooks
    # ------------------------------------------------------------------

    def _on_finding(
        self, payload_dict: dict, response: str, is_vulnerable: bool
    ) -> tuple[bool, str | None]:
        """Hook called after scan_payload() for each payload.

        Subclasses override this to add post-scan analysis (e.g. tool
        extraction in agent, source detection in rag).

        Returns:
            (is_vulnerable, extra_response)  – *extra_response* is appended
            to the Finding response when not ``None``.
        """
        return is_vulnerable, None

    def _on_scan_complete(self) -> None:
        """Hook called after the scan loop finishes.

        Default prints the standard "X successful, Y blocked" summary.
        """
        self._print(
            "info",
            f"{self.stats['success']} successful, {self.stats['blocked']} blocked",
        )

    async def _run_payload_scan(
        self,
        payloads: list[dict],
        *,
        progress_description: str,
        finding_title_prefix: str | None = None,
        sleep_interval: float = 0.3,
        response_limit: int = 2000,
        use_dedup_payload: bool = False,
    ) -> list:
        """Template method that encapsulates the standard scanning flow.

        1. Create connector & connect
        2. Gather context
        3. Generate AI payloads if configured
        4. Progress-tracked loop: scan_payload → _on_finding hook → Finding + db
        5. CircuitBreakerError handling
        6. Connector cleanup in finally
        7. Call _on_scan_complete()
        """
        from rich.progress import track

        from aix.core.reporter import Finding

        title_prefix = finding_title_prefix or self.module_name.title()
        db_key = self.db_module_name or self.module_name.lower()

        connector = self._create_connector()
        await connector.connect()
        await self.gather_context(connector)

        # Generate context-aware payloads if requested
        if self.generate_count > 0 and self.ai_engine and self.context:
            generated = await self.generate_payloads()
            if generated:
                payloads = payloads + generated

        self._print("info", f"Testing {len(payloads)} payloads...")

        try:
            for p in track(
                payloads,
                description=progress_description,
                console=self.console,
                disable=not self.show_progress,
            ):
                self.stats["total"] += 1
                try:
                    # Reset chat ID for fresh conversation per payload
                    if self.new_chat:
                        connector.reset_chat_id()

                    # Generate per-payload conversation ID
                    conv_id = str(uuid.uuid4())

                    is_vulnerable, best_resp = await self.scan_payload(
                        connector, p["payload"], p["indicators"], p["name"]
                    )

                    # Let subclass modify vulnerability decision / add info
                    is_vulnerable, extra_response = self._on_finding(p, best_resp, is_vulnerable)

                    # Save conversation record
                    target_chat_id = connector.current_chat_id
                    self.db.save_conversation(
                        target=self.target,
                        module=db_key,
                        technique=p["name"],
                        transcript=[
                            {"role": "user", "content": p["payload"], "turn_number": 1},
                            {
                                "role": "assistant",
                                "content": (best_resp or "")[:response_limit],
                                "turn_number": 1,
                            },
                        ],
                        turn_count=1,
                        session_id=self.session_id,
                        target_chat_id=target_chat_id,
                        conversation_id=conv_id,
                    )

                    if is_vulnerable:
                        self.stats["success"] += 1
                        self._print("success", "", p["name"], response=best_resp)

                        response_text = best_resp[:response_limit]
                        if extra_response:
                            response_text += extra_response

                        self.findings.append(
                            Finding(
                                title=f"{title_prefix} - {p['name']}",
                                severity=p["severity"],
                                technique=p["name"],
                                payload=p["payload"],
                                response=response_text,
                                target=self.target,
                                reason=self.last_eval_reason,
                                owasp=p.get("owasp", []),
                            )
                        )

                        db_kwargs = {}
                        if use_dedup_payload:
                            db_kwargs["dedup_payload"] = p.get("original_payload", p["payload"])

                        self.db.add_result(
                            self.target,
                            db_key,
                            p["name"],
                            "success",
                            p["payload"],
                            best_resp[:response_limit],
                            p["severity"].value,
                            reason=self.last_eval_reason,
                            owasp=p.get("owasp", []),
                            session_id=self.session_id,
                            conversation_id=conv_id,
                            **db_kwargs,
                        )
                    else:
                        self.stats["blocked"] += 1
                        self._print("blocked", "", p["name"])

                except CircuitBreakerError:
                    break
                except Exception as e:
                    self.stats["blocked"] += 1
                    self._print("error", f"Error testing {p['name']}: {e}")

                await asyncio.sleep(sleep_interval)

        finally:
            await connector.close()

        self._on_scan_complete()
        return self.findings

    async def run(self):
        """Main execution method - usually overridden by subclasses but can provide skeleton"""
        raise NotImplementedError("Subclasses must implement run()")

    async def gather_context(self, connector) -> TargetContext | None:
        """
        Gather context about the target before scanning.
        Only runs if AI Engine is configured with context enabled.
        """
        if not self.ai_engine:
            # No AI engine configured - context gathering not available
            return None

        if not self.ai_engine.enable_context:
            return None

        if not self.quiet:
            self._print("info", "Gathering target context...")

        try:
            self.context = await self.ai_engine.gather_context(connector)
            if self.context and not self.context.is_empty():
                if not self.quiet:
                    self._print_context_summary(self.context)
            return self.context
        except Exception as e:
            if self.verbose:
                self.console.print(f"[yellow][!] Context gathering failed: {e}[/yellow]")
            return None

    def _print_context_summary(self, context: TargetContext) -> None:
        """Print a summary of gathered context."""
        from rich.panel import Panel
        from rich.table import Table

        # Build context table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        # Purpose & Domain (most important)
        if context.purpose:
            table.add_row("Purpose", f"[bold]{context.purpose}[/bold]")
        if context.domain:
            table.add_row("Domain", context.domain)

        # Model info
        if context.model_type:
            table.add_row("Model", context.model_type)

        # Capabilities
        caps = []
        if context.has_rag:
            caps.append("[green]RAG[/green]")
        if context.has_tools:
            caps.append("[green]Tools[/green]")
        if context.capabilities:
            caps.extend(context.capabilities[:3])
        if caps:
            table.add_row("Capabilities", ", ".join(caps))

        # Expected inputs
        if context.expected_inputs:
            table.add_row("Expected Inputs", ", ".join(context.expected_inputs[:4]))

        # Personality
        if context.personality:
            table.add_row("Personality", context.personality)

        # Restrictions
        if context.restrictions:
            table.add_row("Restrictions", ", ".join(context.restrictions[:3]))

        # Suggested attack vectors
        if context.suggested_vectors:
            vectors = ", ".join(context.suggested_vectors[:4])
            table.add_row("Suggested Attacks", f"[yellow]{vectors}[/yellow]")

        self.console.print(
            Panel(table, title="[bold cyan]Target Context[/bold cyan]", border_style="cyan")
        )

    async def generate_payloads(self) -> list[dict]:
        """
        Generate context-aware payloads using AI Engine.
        Returns payloads in scanner-compatible format.
        """
        if not self.ai_engine or not self.context:
            return []

        if self.generate_count <= 0:
            return []

        # Get OWASP category for this module
        owasp_categories = get_owasp_for_module(self.module_name.lower())
        owasp_str = (
            ", ".join([f"{cat.id}: {cat.name}" for cat in owasp_categories])
            if owasp_categories
            else "General"
        )

        self._print("info", f"Generating {self.generate_count} context-aware payloads...")

        try:
            generated = await self.ai_engine.generate_payloads(
                owasp_category=owasp_str,
                attack_type=self.module_name.lower(),
                count=self.generate_count,
            )

            # Convert to payload format expected by scanner
            payloads = []
            for i, g in enumerate(generated):
                technique_name = g.get("technique", f"generated_{i+1}")

                # Get default OWASP for this module
                module_owasp = get_owasp_for_module(self.module_name.lower())

                payloads.append(
                    {
                        "name": f"ai_gen_{technique_name}",
                        "payload": g["payload"],
                        "indicators": [],  # Will use LLM evaluation
                        "severity": Severity.HIGH,
                        "owasp": module_owasp,
                        "rationale": g.get("rationale", ""),
                        "generated": True,
                        "level": 1,
                        "risk": 1,
                    }
                )

                # Print generated payload info
                if self.verbose:
                    self._print("info", f"Generated: {technique_name}")
                    if g.get("rationale"):
                        self._print("detail", f"Rationale: {g['rationale'][:100]}...")

            if payloads and not self.quiet:
                self._print("info", f"Added {len(payloads)} AI-generated payloads")

            return payloads

        except Exception as e:
            self._print("warning", f"Payload generation failed: {e}")
            return []

    async def cleanup(self):
        """Cleanup resources"""
        if self.ai_engine:
            await self.ai_engine.close()
        if self.evaluator:
            await self.evaluator.close()


# Backward compatibility & Missing classes
class TargetProfile:
    """Target profile configuration"""

    def __init__(self, target: str):
        self.target = target


class AttackResult:
    """Attack result container"""

    def __init__(self, success: bool, data: Any = None):
        self.success = success
        self.data = data


class AttackResponse:
    """Attack response wrapper"""

    def __init__(self, response: str):
        self.response = response


AIXScanner = BaseScanner


def run_scanner(scanner_cls, target: str = None, api_key: str = None, **kwargs):
    """
    Helper to run any scanner class with asyncio.
    Handles target validation and common setup.
    """
    if not target:
        Console().print("[red][-][/red] No target specified")
        return

    # Initialize scanner with all arguments
    scanner = scanner_cls(target, api_key=api_key, **kwargs)

    # Run async
    return asyncio.run(scanner.run())
