"""
AIX Connectors

Handles communication with AI targets through various methods:
- Direct API calls (OpenAI, Anthropic, etc.)
- WebSocket connections
- Proxy/intercept mode
"""

import asyncio
import json
import os
import re
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from rich.console import Console

if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest

console = Console()


@dataclass
class ConnectorConfig:
    """Configuration for a connector"""

    url: str
    method: str = "POST"
    headers: dict[str, str] = None
    auth_type: str | None = None
    auth_value: str | None = None
    timeout: int = 30
    message_field: str = "message"
    response_field: str = "response"
    proxy: str | None = None
    cookies: str | None = None
    extra_fields: dict[str, Any] = None


class Connector(ABC):
    """Base class for all connectors"""

    def __init__(self, url: str, profile=None, console=None, **kwargs):
        self.url = url
        self.profile = profile
        self.config = kwargs
        self.session = None
        # Use provided console or fallback to global
        global _global_console
        if "_global_console" not in globals():
            _global_console = Console()
        self.console = console or _global_console

    def _parse_cookies(self, cookies: str | None) -> dict[str, str]:
        """Parse cookie string into dictionary"""
        if not cookies:
            return {}

        cookie_dict = {}
        for item in cookies.split(";"):
            if "=" in item:
                key, value = item.strip().split("=", 1)
                cookie_dict[key] = value
        return cookie_dict

    def _parse_headers(self, headers: str | None) -> dict[str, str]:
        """Parse header string into dictionary"""
        if not headers:
            return {}

        header_dict = {}
        for item in headers.split(";"):
            if ":" in item:
                key, value = item.strip().split(":", 1)
                header_dict[key.strip()] = value.strip()
        return header_dict

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to target"""
        pass

    @abstractmethod
    async def send(self, payload: str) -> str:
        """Send payload and return response"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close connection"""
        pass

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def _apply_regex(self, text: str) -> str:
        """Apply response regex to extracted text"""
        if not hasattr(self, "response_regex") or not self.response_regex or not text:
            return text

        try:
            matches = re.findall(self.response_regex, text, re.DOTALL)
            if matches:
                # Return the LAST match (latest response)
                last_match = matches[-1]
                if isinstance(last_match, tuple):
                    return last_match[0]  # Return content of first capture group
                return last_match
            else:
                # Use shared console to avoid breaking progress bars
                self.console.print(
                    f"[yellow]CONNECTOR[/yellow] [!] Regex '{self.response_regex}' found no matches in response."
                )
                return text
        except re.error as e:
            self.console.print(f"[red]CONNECTOR[/red] [!] Invalid regex: {e}")
            return text


class APIConnector(Connector):
    """
    Direct API connector for OpenAI-compatible APIs.

    Supports:
    - OpenAI API
    - Anthropic API
    - Azure OpenAI
    - Local models (Ollama, LM Studio)
    - Custom APIs
    """

    # Known API formats
    API_FORMATS = {
        "openai": {
            "endpoint": "/v1/chat/completions",
            "message_field": "messages",
            "message_format": lambda m: [{"role": "user", "content": m}],
            "response_path": "choices.0.message.content",
            "headers": {"Content-Type": "application/json"},
        },
        "anthropic": {
            "endpoint": "/v1/messages",
            "message_field": "messages",
            "message_format": lambda m: [{"role": "user", "content": m}],
            "response_path": "content.0.text",
            "headers": {
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
        },
        "ollama": {
            "endpoint": "/api/chat",
            "message_field": "messages",
            "message_format": lambda m: [{"role": "user", "content": m}],
            "response_path": "message.content",
            "headers": {"Content-Type": "application/json"},
        },
        "gemini": {
            "endpoint": ":generateContent",
            "message_field": "contents",
            "message_format": lambda m: [{"parts": [{"text": m}]}],
            "response_path": "candidates.0.content.parts.0.text",
            "headers": {"Content-Type": "application/json"},
        },
        "generic": {
            "endpoint": "",
            "message_field": "message",
            "message_format": lambda m: m,
            "response_path": "response",
            "headers": {"Content-Type": "application/json"},
        },
    }

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        api_format: str = "generic",
        model: str | None = None,
        profile=None,
        **kwargs,
    ):
        super().__init__(url, profile, **kwargs)
        self.api_key = api_key
        self.api_format = api_format
        self.model = model
        self.model = model
        self.injection_param = kwargs.get("injection_param")
        self.body_format = kwargs.get("body_format", "json")
        self.client: httpx.AsyncClient | None = None
        self.refresh_config = kwargs.get("refresh_config", {})
        self.response_regex = kwargs.get("response_regex")
        self.response_path = kwargs.get("response_path")

        # Detect API format from URL if not specified
        if api_format == "generic":
            self.api_format = self._detect_api_format()

        self.format_config = self.API_FORMATS.get(self.api_format, self.API_FORMATS["generic"])

    def _detect_api_format(self) -> str:
        """Detect API format from URL"""
        url_lower = self.url.lower()

        if "openai" in url_lower or "azure" in url_lower:
            return "openai"
        elif "anthropic" in url_lower:
            return "anthropic"
        elif "ollama" in url_lower or ":11434" in url_lower:
            return "ollama"
        elif "generativelanguage.googleapis.com" in url_lower:
            return "gemini"

        return "generic"

    def _build_headers(self) -> dict[str, str]:
        """Build request headers"""
        headers = dict(self.format_config.get("headers", {}))

        # Remove default Content-Type if not using JSON format so httpx can set it correctly
        if self.body_format != "json" and headers.get("Content-Type") == "application/json":
            del headers["Content-Type"]

        if self.api_key:
            if self.api_format == "anthropic":
                headers["x-api-key"] = self.api_key
            elif self.api_format == "gemini":
                headers["x-goog-api-key"] = self.api_key
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"

        # Add custom headers from profile
        if self.profile and hasattr(self.profile, "headers"):
            headers.update(self.profile.headers or {})

        # Add custom headers from CLI
        custom_headers = self._parse_headers(self.config.get("headers"))
        if custom_headers:
            headers.update(custom_headers)

        return headers

    def _build_payload(self, message: str) -> dict[str, Any]:
        """Build request payload"""
        msg_field = self.injection_param or self.format_config["message_field"]
        msg_format = self.format_config["message_format"]

        payload = {
            msg_field: msg_format(message),
        }

        # Add model if specified
        if self.model:
            payload["model"] = self.model
        elif self.api_format == "openai":
            payload["model"] = "gpt-4"
        elif self.api_format == "anthropic":
            payload["model"] = "claude-3-sonnet-20240229"
            payload["max_tokens"] = 1024

        # Add extra fields from profile
        if self.profile and hasattr(self.profile, "request_template"):
            template = self.profile.request_template or {}
            for key, value in template.items():
                if key not in payload:
                    payload[key] = value

        return payload

    def _extract_response(self, data: dict[str, Any]) -> str:
        """Extract response text from API response"""

        # Helper to extract from data structure
        def extract_from_path(d, p):
            result = d
            for key in p.split("."):
                if isinstance(result, list):
                    if key.isdigit() and int(key) < len(result):
                        result = result[int(key)]
                    else:
                        return ""
                elif isinstance(result, dict):
                    result = result.get(key, "")
                else:
                    return str(result)

                if result is None:
                    return ""
            return str(result) if result is not None else ""

        extracted_text = ""
        path = self.format_config["response_path"]

        # Priority: CLI option > profile > format default
        if self.response_path:
            path = self.response_path
        elif self.profile and hasattr(self.profile, "response_path") and self.profile.response_path:
            path = self.profile.response_path

        extracted_text = extract_from_path(data, path)
        return self._apply_regex(extracted_text)

    async def connect(self) -> None:
        """Initialize HTTP client"""
        # Determine explicit proxy setting (connector config overrides env)
        proxy = (
            self.config.get("proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        )
        if proxy and not (proxy.startswith("http://") or proxy.startswith("https://")):
            proxy = "http://" + proxy

        # Verbose log about proxy
        try:
            verbose = int(self.config.get("verbose", 0))
        except Exception:
            verbose = 0

        if verbose >= 3:
            if proxy:
                console.print(f"[cyan]CONNECTOR[/cyan] [*] Using proxy: {proxy}")

            # Parse cookies
            cookies = self._parse_cookies(self.config.get("cookies"))
            if cookies:
                console.print(f"[cyan]CONNECTOR[/cyan] [*] Using cookies: {list(cookies.keys())}")
        else:
            cookies = self._parse_cookies(self.config.get("cookies"))

        self.client = httpx.AsyncClient(
            timeout=self.config.get("timeout", 30),
            follow_redirects=True,
            trust_env=False,
            proxy=proxy,
            cookies=cookies,
            verify=False,  # Disable SSL verification for proxying (Burp/ZAP)
            http2=True,  # Enable HTTP/2 support for modern APIs (OpenAI, Anthropic, etc.)
        )

    async def _refresh_session(self) -> bool:
        """
        Attempt to refresh the session ID/token.
        Returns True if successful, False otherwise.
        """
        refresh_url = self.refresh_config.get("url")
        refresh_regex = self.refresh_config.get("regex")
        refresh_param = self.refresh_config.get("param")

        if not refresh_url or not refresh_regex or not refresh_param:
            return False

        console.print(
            "[yellow]CONNECTOR[/yellow] [!] Session expired or error detected. Attempting refresh..."
        )
        console.print(f"[yellow]CONNECTOR[/yellow] [*] Fetching fresh token from: {refresh_url}")

        try:
            # Create a localized client for the refresh
            proxy = self.config.get("proxy")
            if proxy and not (proxy.startswith("http://") or proxy.startswith("https://")):
                proxy = "http://" + proxy

            # EXPLICITLY disable redirect following to capture Location header
            async with httpx.AsyncClient(
                proxy=proxy, verify=False, trust_env=False, follow_redirects=False
            ) as client:
                response = await client.get(refresh_url)

                content_to_search = ""

                # Check for Redirect (3xx)
                if 300 <= response.status_code < 400:
                    console.print(
                        f"[cyan]CONNECTOR[/cyan] [*] Refresh endpoint returned redirect: {response.status_code}"
                    )
                    if "Location" in response.headers:
                        content_to_search = response.headers["Location"]
                        # Append to current text just in case regex needs more context or body has it
                        # But usually Location is just the URL.
                    else:
                        console.print(
                            "[red]CONNECTOR[/red] [-] Redirect caught but no Location header found"
                        )

                # Check for Success (2xx)
                elif 200 <= response.status_code < 300:
                    content_to_search = response.text

                # Errors
                else:
                    console.print(
                        f"[red]CONNECTOR[/red] [-] Refresh request failed with status: {response.status_code}"
                    )
                    return False

                # Extract new ID using regex
                match = re.search(refresh_regex, content_to_search)
                if match:
                    new_id = match.group(1)
                    console.print(f"[green]CONNECTOR[/green] [+] Refreshed session ID: {new_id}")

                    # Update the target URL with the new parameter
                    parsed_url = urllib.parse.urlparse(self.url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    query_params[refresh_param] = [new_id]

                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    self.url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

                    console.print(f"[green]CONNECTOR[/green] [*] Updated target: {self.url}")
                    return True
                else:
                    console.print(
                        f"[red]CONNECTOR[/red] [-] Could not extract session ID using regex: {refresh_regex}"
                    )
                    if 300 <= response.status_code < 400:
                        console.print(
                            f"[red]CONNECTOR[/red] [-] Checked Location: {content_to_search}"
                        )
                    return False

        except Exception as e:
            console.print(f"[red]CONNECTOR[/red] [-] Refresh failed: {e}")
            return False

    async def send_with_messages(self, messages: list[dict]) -> str:
        """
        Send request with full conversation history (multi-turn support).

        Args:
            messages: List of message dicts with 'role' and 'content' keys

        Returns:
            Model's response text
        """
        if not self.client:
            await self.connect()

        # Build URL with endpoint
        endpoint = self.format_config.get("endpoint", "")
        if self.url.rstrip("/").endswith(endpoint.rstrip("/")):
            url = self.url
        else:
            url = self.url.rstrip("/") + endpoint

        headers = self._build_headers()

        # Build payload with messages array
        body = {}

        # Add model
        if self.model:
            body["model"] = self.model
        elif self.api_format == "openai":
            body["model"] = "gpt-4"
        elif self.api_format == "anthropic":
            body["model"] = "claude-3-sonnet-20240229"
            body["max_tokens"] = 4096

        # Format messages based on API type
        if self.api_format == "gemini":
            # Gemini uses 'contents' with different format
            body["contents"] = [
                {
                    "role": "user" if m["role"] == "user" else "model",
                    "parts": [{"text": m["content"]}],
                }
                for m in messages
            ]
        else:
            # OpenAI/Anthropic/Ollama use 'messages'
            body["messages"] = messages

        try:
            response = await self.client.post(url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
            return self._extract_response(data)

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            error_msg = f"HTTP {status}"
            if status in [401, 403]:
                error_msg += " (Authentication Failed)"
            elif status == 429:
                error_msg += " (Rate Limit Exceeded)"
            elif status >= 500:
                error_msg += " (Server Error)"
            raise ConnectionError(f"{error_msg}: {e.response.text[:200]}")
        except Exception as e:
            raise ConnectionError(f"Request failed: {e!s}")

    async def send(self, payload: str) -> str:
        """Send message to API and return response"""
        if not self.client:
            await self.connect()

        # Retry loop for session refresh
        max_retries = 1
        attempt = 0

        while attempt <= max_retries:
            attempt += 1

            # Build URL with endpoint
            endpoint = self.format_config.get("endpoint", "")
            if self.url.rstrip("/").endswith(endpoint.rstrip("/")):
                url = self.url
            else:
                url = self.url.rstrip("/") + endpoint

            # Use profile URL if available
            if self.profile and self.profile.endpoint:
                url = self.profile.url.rstrip("/") + self.profile.endpoint

            headers = self._build_headers()
            body = self._build_payload(payload)

            try:
                if self.body_format == "json":
                    response = await self.client.post(url, json=body, headers=headers)
                elif self.body_format == "form":
                    response = await self.client.post(url, data=body, headers=headers)
                elif self.body_format == "multipart":
                    files = (
                        {k: (None, str(v)) for k, v in body.items()}
                        if isinstance(body, dict)
                        else body
                    )
                    response = await self.client.post(url, files=files, headers=headers)
                else:
                    response = await self.client.post(url, json=body, headers=headers)

                # Check for triggering conditions for refresh
                should_refresh = False

                # 1. HTTP Error Status codes
                if response.status_code in [401, 403, 500]:
                    should_refresh = True

                # 2. Content-based error trigger (for 200 OK errors)
                refresh_error_sig = self.refresh_config.get("error")
                if refresh_error_sig:
                    if re.search(refresh_error_sig, response.text):
                        console.print(
                            f"[yellow]CONNECTOR[/yellow] [!] Response matches error signature: '{refresh_error_sig}'"
                        )
                        should_refresh = True

                # Perform refresh if needed and we haven't retried yet
                if should_refresh and self.refresh_config.get("url") and attempt <= max_retries:
                    if await self._refresh_session():
                        continue  # Retry loop with new URL
                    else:
                        # Refresh failed, let it error out naturally or return the error response
                        pass

                response.raise_for_status()

                data = response.json()
                return self._extract_response(data)

            except httpx.HTTPStatusError as e:
                # If we are here, it means we either didn't refresh or refresh failed
                status = e.response.status_code
                # We raise the error but do not print here to avoid spamming the console
                # The caller (scanner) should handle the display of errors.

                error_msg = f"HTTP {status}"
                if status in [401, 403]:
                    error_msg += " (Authentication Failed)"
                elif status == 429:
                    error_msg += " (Rate Limit Exceeded)"
                elif status >= 500:
                    error_msg += " (Server Error)"

                raise ConnectionError(f"{error_msg}: {e.response.text[:200]}")
            except json.JSONDecodeError:
                # Check for content error match on non-JSON response too
                refresh_error_sig = self.refresh_config.get("error")
                if refresh_error_sig and attempt <= max_retries and self.refresh_config.get("url"):
                    # We might have failed JSON decode because of an error page
                    if re.search(refresh_error_sig, response.text):
                        console.print(
                            "[yellow]CONNECTOR[/yellow] [!] Response matches error signature (Auto-Refresh Triggered)"
                        )
                        if await self._refresh_session():
                            continue  # Retry loop

                return self._apply_regex(response.text)
            except httpx.ConnectError:
                raise ConnectionError(f"Failed to connect to {url}. Check your proxy settings.")
            except Exception as e:
                raise ConnectionError(f"Request failed: {e!s}")

    async def close(self) -> None:
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None


class WebSocketConnector(Connector):
    """
    WebSocket connector for real-time chat interfaces.
    """

    def __init__(self, url: str, profile=None, **kwargs):
        super().__init__(url, profile, **kwargs)
        self.ws = None
        self.message_format = kwargs.get("message_format", lambda m: json.dumps({"message": m}))
        self.response_parser = kwargs.get(
            "response_parser", lambda r: json.loads(r).get("response", r)
        )

    async def connect(self) -> None:
        """Connect to WebSocket"""
        import websockets

        self.ws = await websockets.connect(self.url)

    async def send(self, payload: str) -> str:
        """Send message through WebSocket"""
        if not self.ws:
            await self.connect()

        await self.ws.send(self.message_format(payload))
        response = await self.ws.recv()
        return self.response_parser(response)

    async def close(self) -> None:
        """Close WebSocket"""
        if self.ws:
            await self.ws.close()


class InterceptConnector(Connector):
    """
    Proxy connector for intercepting and modifying traffic.

    Works with mitmproxy to intercept, analyze, and modify
    requests between client and AI backend.
    """

    def __init__(self, url: str, profile=None, port: int = 8080, **kwargs):
        super().__init__(url, profile, **kwargs)
        self.port = port
        self.intercepted_requests: list[dict] = []
        self.intercepted_responses: list[dict] = []
        self.server = None
        # Optional upstream proxy to forward requests to (host, port)
        self.upstream = kwargs.get("upstream")

    async def connect(self) -> None:
        """Start proxy server"""
        console.print(f"[cyan][*][/cyan] Starting TCP proxy on 127.0.0.1:{self.port}")
        console.print("[cyan][*][/cyan] Configure your browser to use this proxy")

        self.server = await asyncio.start_server(self._handle_client, "127.0.0.1", self.port)

    async def send(self, payload: str) -> str:
        """In intercept mode, we modify requests rather than send them"""
        raise NotImplementedError("Use intercept mode to capture and modify requests")

    async def close(self) -> None:
        """Stop proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    def get_intercepted(self) -> list[dict]:
        """Get list of intercepted request/response pairs"""
        return list(zip(self.intercepted_requests, self.intercepted_responses))

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection and forward to upstream (if set) or act as simple forwarder."""
        peer = writer.get_extra_info("peername")
        console.print(f"[cyan][*][/cyan] Connection from {peer}")

        upstream_reader = None
        upstream_writer = None

        try:
            if self.upstream:
                uhost, uport = self.upstream
                upstream_reader, upstream_writer = await asyncio.open_connection(uhost, uport)
            else:
                # If no upstream is provided, try to parse host from the first client bytes
                # We'll still forward raw bytes but without upstream we'll echo an error.
                # For now, refuse connection.
                console.print(
                    "[yellow][!][/yellow] No upstream configured — proxy will accept connections but not forward them."
                )
                writer.close()
                await writer.wait_closed()
                return

            # Pump data between client and upstream
            async def pump(src_reader, dst_writer, capture_list, is_request=True):
                buffer = b""
                first_chunk = True
                while True:
                    data = await src_reader.read(4096)
                    if not data:
                        break
                    dst_writer.write(data)
                    await dst_writer.drain()

                    # capture initial headers/text for logging
                    if first_chunk:
                        buffer += data
                        first_chunk = False
                        try:
                            # try decode headers
                            text = buffer.decode("utf-8", errors="replace")
                        except Exception:
                            text = repr(buffer)
                        capture_list.append({"peer": peer, "data": text})

                try:
                    dst_writer.write_eof()
                except Exception:
                    pass

            # Run two pumps concurrently
            task1 = asyncio.create_task(
                pump(reader, upstream_writer, self.intercepted_requests, True)
            )
            task2 = asyncio.create_task(
                pump(upstream_reader, writer, self.intercepted_responses, False)
            )

            await asyncio.gather(task1, task2)

        except Exception as e:
            console.print(f"[red][-][/red] Proxy error: {e}")
        finally:
            try:
                if upstream_writer:
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class RequestConnector(Connector):
    """
    Connector that uses a parsed HTTP request file.

    Allows testing with exact request format captured from
    Burp Suite or similar proxy tools.
    """

    def __init__(self, parsed_request: "ParsedRequest", response_path: str | None = None, **kwargs):
        super().__init__(parsed_request.url, **kwargs)
        self.parsed_request = parsed_request
        self.response_path = response_path
        self.response_regex = kwargs.get("response_regex")
        self.client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Initialize HTTP client"""
        # Determine explicit proxy setting (connector config overrides env)
        proxy = (
            self.config.get("proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        )
        if proxy and not (proxy.startswith("http://") or proxy.startswith("https://")):
            proxy = "http://" + proxy

        # Verbose log about proxy
        # Verbose log about proxy
        try:
            verbose = int(self.config.get("verbose", 0))
        except Exception:
            verbose = 0
        # Parse cookies
        cookies = self._parse_cookies(self.config.get("cookies"))

        if verbose >= 1 and proxy:
            # Level 1 is enough for proxy notice, maybe? Or keep it quiet?
            # User wants CLEAN logs. Proxy usage info is "meta". Let's put it on Level 2 (debug) or Level 1?
            # User complaint was about Headers dump.
            # Let's keep Proxy info at Level 2 to be safe for "clean" Level 1.
            pass

        # Parse cookies
        cookies = self._parse_cookies(self.config.get("cookies"))

        if verbose >= 3:
            if proxy:
                console.print(f"[cyan]REQUEST-CONN[/cyan] [*] Using proxy: {proxy}")
            if cookies:
                console.print(
                    f"[cyan]REQUEST-CONN[/cyan] [*] Using cookies: {list(cookies.keys())}"
                )

        self.client = httpx.AsyncClient(
            timeout=self.config.get("timeout", 30),
            follow_redirects=True,
            trust_env=False,
            proxy=proxy,
            cookies=cookies,
            verify=False,  # Disable SSL verification for proxying (Burp/ZAP)
            http2=True,  # Enable HTTP/2 support for modern APIs (OpenAI, Anthropic, etc.)
        )

    async def send(self, payload: str) -> str:
        """Send request with payload injected at specified parameter"""
        if not self.client:
            await self.connect()

        from aix.core.request_parser import inject_payload

        # Inject payload into request
        injected_request = inject_payload(self.parsed_request, payload)

        # Build headers (exclude Host and Content-Length as httpx handles them)
        headers = {
            k: v
            for k, v in injected_request.headers.items()
            if k.lower() not in ("host", "content-length")
        }

        # Add custom headers from CLI
        custom_headers = self._parse_headers(self.config.get("headers"))
        if custom_headers:
            headers.update(custom_headers)

        try:
            # Verbose logging for debugging proxy usage
            # Verbose logging for debugging proxy usage
            try:
                verbose = int(self.config.get("verbose", 0))
            except Exception:
                verbose = 0
            if verbose >= 3:
                console.print(
                    f"[cyan]REQUEST-CONN[/cyan] [*] {injected_request.method} {injected_request.url}"
                )
                console.print(f"[cyan]REQUEST-CONN[/cyan] [*] Headers: {injected_request.headers}")
                console.print(
                    f"[cyan]REQUEST-CONN[/cyan] [*] Body present: {bool(injected_request.body)}"
                )
            if injected_request.method.upper() == "POST":
                if injected_request.is_json:
                    response = await self.client.post(
                        injected_request.url, json=injected_request.body_json, headers=headers
                    )
                else:
                    response = await self.client.post(
                        injected_request.url, content=injected_request.body, headers=headers
                    )
            elif injected_request.method.upper() == "GET":
                response = await self.client.get(injected_request.url, headers=headers)
            else:
                response = await self.client.request(
                    injected_request.method,
                    injected_request.url,
                    content=injected_request.body,
                    headers=headers,
                )

            response.raise_for_status()

            # Try to parse JSON response
            try:
                data = response.json()
                return self._extract_response(data)
            except json.JSONDecodeError:
                return self._apply_regex(response.text)

        except httpx.HTTPStatusError as e:
            status = e.response.status_code

            error_msg = f"HTTP {status}"
            if status in [401, 403]:
                error_msg += " (Authentication Failed)"
            elif status == 429:
                error_msg += " (Rate Limit Exceeded)"
            elif status >= 500:
                error_msg += " (Server Error)"

            raise ConnectionError(f"{error_msg}: {e.response.text[:200]}")
        except httpx.ConnectError:
            raise ConnectionError(
                f"Failed to connect to {injected_request.url}. Check your proxy settings."
            )
        except Exception as e:
            raise ConnectionError(f"Request failed: {e!s}")

    def _extract_response(self, data: Any) -> str:
        """Extract response text from API response"""
        extracted_text = ""

        if not self.response_path:
            # Try common response paths
            common_paths = [
                "choices.0.message.content",  # OpenAI
                "content.0.text",  # Anthropic
                "message.content",  # Ollama
                "response",  # Generic
                "text",  # Simple
                "output",  # Alternative
            ]
            for path in common_paths:
                try:
                    result = self._navigate_path(data, path)
                    if result:
                        extracted_text = str(result)
                        break
                except (KeyError, IndexError, TypeError):
                    continue

            # If still empty, use full dump
            if not extracted_text:
                extracted_text = json.dumps(data) if isinstance(data, dict) else str(data)

        else:
            extracted_text = str(self._navigate_path(data, self.response_path))

        return self._apply_regex(extracted_text)

    def _navigate_path(self, data: Any, path: str) -> Any:
        """Navigate nested path in response data"""
        result = data
        for key in path.split("."):
            if isinstance(result, list):
                if key.isdigit() and int(key) < len(result):
                    result = result[int(key)]
                else:
                    return ""
            elif isinstance(result, dict):
                result = result.get(key, "")
            else:
                return str(result)

            if not result:
                break
        return result

    async def close(self) -> None:
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None
