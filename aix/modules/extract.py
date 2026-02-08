"""AIX Extract Module - System prompt extraction"""

from typing import TYPE_CHECKING, Optional

from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class ExtractScanner(BaseScanner):
    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        browser: bool = False,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        **kwargs,
    ):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "EXTRACT"
        self.console_color = "cyan"
        self.browser = browser
        self.default_extractions = self.load_payloads("extract.json")

    async def run(self, extractions: list[dict] = None):
        if extractions is None:
            extractions = self.default_extractions

        return await self._run_payload_scan(
            extractions,
            progress_description="[bold green]📥 Siphoning Data...  [/]",
            finding_title_prefix="Extraction",
        )


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(ExtractScanner, target, api_key=api_key, **kwargs)
