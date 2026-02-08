"""AIX Inject Module - Prompt injection attacks"""

from typing import TYPE_CHECKING, Optional

from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class InjectScanner(BaseScanner):
    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        **kwargs,
    ):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "INJECT"
        self.console_color = "cyan"
        self.default_payloads = self.load_payloads("inject.json")

    async def run(self, payloads: list[dict] = None):
        if payloads is None:
            payloads = self.default_payloads

        return await self._run_payload_scan(
            payloads,
            progress_description="[bold cyan]💉 Injecting Vectors...[/]",
            finding_title_prefix="Injection",
            use_dedup_payload=True,
        )


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(InjectScanner, target, api_key=api_key, **kwargs)
