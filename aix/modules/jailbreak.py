"""AIX Jailbreak Module - Bypass AI restrictions"""

from typing import TYPE_CHECKING, Optional

from aix.core.scanner import BaseScanner, run_scanner

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest


class JailbreakScanner(BaseScanner):
    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        verbose: bool = False,
        parsed_request: Optional["ParsedRequest"] = None,
        **kwargs,
    ):
        super().__init__(target, api_key, verbose, parsed_request, **kwargs)
        self.module_name = "JAILBRK"
        self.db_module_name = "jailbreak"
        self.console_color = "cyan"
        self.test_harmful = kwargs.get("test_harmful", False)
        self.default_jailbreaks = self.load_payloads("jailbreak.json")

    async def run(self, jailbreaks: list[dict] = None):
        if jailbreaks is None:
            jailbreaks = self.default_jailbreaks

        return await self._run_payload_scan(
            jailbreaks,
            progress_description="[bold red]🔓 Breaking Rails...   [/]",
            finding_title_prefix="Jailbreak",
            sleep_interval=0.5,
            use_dedup_payload=True,
        )


def run(target: str = None, api_key: str = None, **kwargs):
    run_scanner(JailbreakScanner, target, api_key=api_key, **kwargs)
