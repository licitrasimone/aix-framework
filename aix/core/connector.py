"""
AIX Connectors

Handles communication with AI targets through various methods:
- Direct API calls (OpenAI, Anthropic, etc.)
- Browser-based interaction (for JS-heavy sites)
- WebSocket connections
- Proxy/intercept mode
"""

import asyncio
import json
import re
import os
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import httpx
from rich.console import Console

console = Console()


@dataclass
class ConnectorConfig:
    """Configuration for a connector"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = None
    auth_type: Optional[str] = None
    auth_value: Optional[str] = None
    timeout: int = 30
    message_field: str = "message"
    response_field: str = "response"
    extra_fields: Dict[str, Any] = None


class Connector(ABC):
    """Base class for all connectors"""
    
    def __init__(self, url: str, profile=None, **kwargs):
        self.url = url
        self.profile = profile
        self.config = kwargs
        self.session = None
    
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
        'openai': {
            'endpoint': '/v1/chat/completions',
            'message_field': 'messages',
            'message_format': lambda m: [{"role": "user", "content": m}],
            'response_path': 'choices.0.message.content',
            'headers': {'Content-Type': 'application/json'},
        },
        'anthropic': {
            'endpoint': '/v1/messages',
            'message_field': 'messages',
            'message_format': lambda m: [{"role": "user", "content": m}],
            'response_path': 'content.0.text',
            'headers': {
                'Content-Type': 'application/json',
                'anthropic-version': '2023-06-01',
            },
        },
        'ollama': {
            'endpoint': '/api/chat',
            'message_field': 'messages',
            'message_format': lambda m: [{"role": "user", "content": m}],
            'response_path': 'message.content',
            'headers': {'Content-Type': 'application/json'},
        },
        'generic': {
            'endpoint': '',
            'message_field': 'message',
            'message_format': lambda m: m,
            'response_path': 'response',
            'headers': {'Content-Type': 'application/json'},
        },
    }
    
    def __init__(
        self,
        url: str,
        api_key: Optional[str] = None,
        api_format: str = 'generic',
        model: Optional[str] = None,
        profile=None,
        **kwargs
    ):
        super().__init__(url, profile, **kwargs)
        self.api_key = api_key
        self.api_format = api_format
        self.model = model
        self.client: Optional[httpx.AsyncClient] = None
        
        # Detect API format from URL if not specified
        if api_format == 'generic':
            self.api_format = self._detect_api_format()
        
        self.format_config = self.API_FORMATS.get(self.api_format, self.API_FORMATS['generic'])
    
    def _detect_api_format(self) -> str:
        """Detect API format from URL"""
        url_lower = self.url.lower()
        
        if 'openai' in url_lower or 'azure' in url_lower:
            return 'openai'
        elif 'anthropic' in url_lower:
            return 'anthropic'
        elif 'ollama' in url_lower or ':11434' in url_lower:
            return 'ollama'
        
        return 'generic'
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers"""
        headers = dict(self.format_config.get('headers', {}))
        
        if self.api_key:
            if self.api_format == 'anthropic':
                headers['x-api-key'] = self.api_key
            else:
                headers['Authorization'] = f'Bearer {self.api_key}'
        
        # Add custom headers from profile
        if self.profile and hasattr(self.profile, 'headers'):
            headers.update(self.profile.headers or {})
        
        return headers
    
    def _build_payload(self, message: str) -> Dict[str, Any]:
        """Build request payload"""
        msg_field = self.format_config['message_field']
        msg_format = self.format_config['message_format']
        
        payload = {
            msg_field: msg_format(message),
        }
        
        # Add model if specified
        if self.model:
            payload['model'] = self.model
        elif self.api_format == 'openai':
            payload['model'] = 'gpt-4'
        elif self.api_format == 'anthropic':
            payload['model'] = 'claude-3-sonnet-20240229'
            payload['max_tokens'] = 1024
        
        # Add extra fields from profile
        if self.profile and hasattr(self.profile, 'request_template'):
            template = self.profile.request_template or {}
            for key, value in template.items():
                if key not in payload:
                    payload[key] = value
        
        return payload
    
    def _extract_response(self, data: Dict[str, Any]) -> str:
        """Extract response text from API response"""
        path = self.format_config['response_path']
        
        # Handle profile-specific response path
        if self.profile and hasattr(self.profile, 'response_path'):
            path = self.profile.response_path
        
        # Navigate nested path like "choices.0.message.content"
        result = data
        for key in path.split('.'):
            if key.isdigit():
                result = result[int(key)]
            else:
                result = result.get(key, '')
            
            if not result:
                break
        
        return str(result) if result else ""
    
    async def connect(self) -> None:
        """Initialize HTTP client"""
        # Determine explicit proxy setting (connector config overrides env)
        proxy = self.config.get('proxy') or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        if proxy and not (proxy.startswith('http://') or proxy.startswith('https://')):
            proxy = 'http://' + proxy

        # If an explicit proxy was provided, set env vars so httpx with trust_env=True uses it
        if proxy:
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy

        # Verbose log about proxy
        try:
            verbose = bool(self.config.get('verbose'))
        except Exception:
            verbose = False
        if verbose:
            console.print(f"[cyan]CONNECTOR[/cyan] [*] Using proxy: {proxy}")

        self.client = httpx.AsyncClient(
            timeout=self.config.get('timeout', 30),
            follow_redirects=True,
            trust_env=True,
        )
    
    async def send(self, payload: str) -> str:
        """Send message to API and return response"""
        if not self.client:
            await self.connect()
        
        # Build URL with endpoint
        endpoint = self.format_config.get('endpoint', '')
        url = self.url.rstrip('/') + endpoint
        
        # Use profile URL if available
        if self.profile and self.profile.endpoint:
            url = self.profile.url.rstrip('/') + self.profile.endpoint
        
        headers = self._build_headers()

        # Verbose logging for debugging proxy usage
        try:
            verbose = bool(self.config.get('verbose'))
        except Exception:
            verbose = False
        if verbose:
            console.print(f"[cyan]CONNECTOR[/cyan] [*] POST {url}")
            console.print(f"[cyan]CONNECTOR[/cyan] [*] Headers: {headers}")
            console.print(f"[cyan]CONNECTOR[/cyan] [*] Body keys: {list(body.keys()) if isinstance(body, dict) else 'raw'}")
        body = self._build_payload(payload)
        
        try:
            response = await self.client.post(url, json=body, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            return self._extract_response(data)
        
        except httpx.HTTPStatusError as e:
            raise ConnectionError(f"HTTP {e.response.status_code}: {e.response.text[:200]}")
        except json.JSONDecodeError:
            return response.text
        except Exception as e:
            raise ConnectionError(f"Request failed: {str(e)}")
    
    async def close(self) -> None:
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None


class WebConnector(Connector):
    """
    Browser-based connector using Playwright.
    
    For JavaScript-heavy sites, anti-bot protection, etc.
    """
    
    def __init__(
        self,
        url: str,
        profile=None,
        headless: bool = True,
        **kwargs
    ):
        super().__init__(url, profile, **kwargs)
        self.headless = headless
        self.browser = None
        self.context = None
        self.page = None
        
        # Selectors for common chat interfaces
        self.input_selector = kwargs.get('input_selector', 'textarea, input[type="text"]')
        self.submit_selector = kwargs.get('submit_selector', 'button[type="submit"], button:has-text("Send")')
        self.response_selector = kwargs.get('response_selector', '.response, .message, .chat-message')
    
    async def connect(self) -> None:
        """Launch browser and navigate to target"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for browser mode. "
                "Install with: pip install playwright && playwright install"
            )
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context()
        self.page = await self.context.new_page()
        
        await self.page.goto(self.url)
        await self.page.wait_for_load_state('networkidle')
    
    async def send(self, payload: str) -> str:
        """Send message through browser and capture response"""
        if not self.page:
            await self.connect()
        
        # Find and fill input
        input_el = await self.page.wait_for_selector(self.input_selector, timeout=5000)
        await input_el.fill(payload)
        
        # Click submit
        submit_el = await self.page.wait_for_selector(self.submit_selector, timeout=5000)
        await submit_el.click()
        
        # Wait for response
        await self.page.wait_for_timeout(2000)  # Wait for AI to respond
        
        # Get response text
        response_els = await self.page.query_selector_all(self.response_selector)
        if response_els:
            # Get last response (the AI's reply)
            last_response = response_els[-1]
            return await last_response.inner_text()
        
        return ""
    
    async def close(self) -> None:
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright') and self.playwright:
            await self.playwright.stop()


class WebSocketConnector(Connector):
    """
    WebSocket connector for real-time chat interfaces.
    """
    
    def __init__(self, url: str, profile=None, **kwargs):
        super().__init__(url, profile, **kwargs)
        self.ws = None
        self.message_format = kwargs.get('message_format', lambda m: json.dumps({"message": m}))
        self.response_parser = kwargs.get('response_parser', lambda r: json.loads(r).get('response', r))
    
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
        self.intercepted_requests: List[Dict] = []
        self.intercepted_responses: List[Dict] = []
        self.server = None
        # Optional upstream proxy to forward requests to (host, port)
        self.upstream = kwargs.get('upstream')

    async def connect(self) -> None:
        """Start proxy server"""
        console.print(f"[cyan][*][/cyan] Starting TCP proxy on 127.0.0.1:{self.port}")
        console.print(f"[cyan][*][/cyan] Configure your browser to use this proxy")

        loop = asyncio.get_event_loop()
        self.server = await asyncio.start_server(self._handle_client, '127.0.0.1', self.port)

    async def send(self, payload: str) -> str:
        """In intercept mode, we modify requests rather than send them"""
        raise NotImplementedError("Use intercept mode to capture and modify requests")

    async def close(self) -> None:
        """Stop proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    def get_intercepted(self) -> List[Dict]:
        """Get list of intercepted request/response pairs"""
        return list(zip(self.intercepted_requests, self.intercepted_responses))

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection and forward to upstream (if set) or act as simple forwarder."""
        peer = writer.get_extra_info('peername')
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
                console.print("[yellow][!][/yellow] No upstream configured — proxy will accept connections but not forward them.")
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
                            text = buffer.decode('utf-8', errors='replace')
                        except Exception:
                            text = repr(buffer)
                        capture_list.append({'peer': peer, 'data': text})

                try:
                    dst_writer.write_eof()
                except Exception:
                    pass

            # Run two pumps concurrently
            task1 = asyncio.create_task(pump(reader, upstream_writer, self.intercepted_requests, True))
            task2 = asyncio.create_task(pump(upstream_reader, writer, self.intercepted_responses, False))

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

    def __init__(
        self,
        parsed_request: 'ParsedRequest',
        response_path: Optional[str] = None,
        **kwargs
    ):
        super().__init__(parsed_request.url, **kwargs)
        self.parsed_request = parsed_request
        self.response_path = response_path
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        """Initialize HTTP client"""
        # Determine explicit proxy setting (connector config overrides env)
        proxy = self.config.get('proxy') or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        if proxy and not (proxy.startswith('http://') or proxy.startswith('https://')):
            proxy = 'http://' + proxy

        # If an explicit proxy was provided, set env vars so httpx with trust_env=True uses it
        if proxy:
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy

        # Verbose log about proxy
        try:
            verbose = bool(self.config.get('verbose'))
        except Exception:
            verbose = False
        if verbose:
            console.print(f"[cyan]REQUEST-CONN[/cyan] [*] Using proxy: {proxy}")

        self.client = httpx.AsyncClient(
            timeout=self.config.get('timeout', 30),
            follow_redirects=True,
            trust_env=True,
        )

    async def send(self, payload: str) -> str:
        """Send request with payload injected at specified parameter"""
        if not self.client:
            await self.connect()

        from aix.core.request_parser import inject_payload

        # Inject payload into request
        injected_request = inject_payload(self.parsed_request, payload)

        # Build headers (exclude Host as httpx handles it)
        headers = {k: v for k, v in injected_request.headers.items()
                   if k.lower() != 'host'}

        try:
            # Verbose logging for debugging proxy usage
            try:
                verbose = bool(self.config.get('verbose'))
            except Exception:
                verbose = False
            if verbose:
                console.print(f"[cyan]REQUEST-CONN[/cyan] [*] {injected_request.method} {injected_request.url}")
                console.print(f"[cyan]REQUEST-CONN[/cyan] [*] Headers: {injected_request.headers}")
                console.print(f"[cyan]REQUEST-CONN[/cyan] [*] Body present: {bool(injected_request.body)}")
            if injected_request.method.upper() == 'POST':
                if injected_request.is_json:
                    response = await self.client.post(
                        injected_request.url,
                        json=injected_request.body_json,
                        headers=headers
                    )
                else:
                    response = await self.client.post(
                        injected_request.url,
                        content=injected_request.body,
                        headers=headers
                    )
            elif injected_request.method.upper() == 'GET':
                response = await self.client.get(
                    injected_request.url,
                    headers=headers
                )
            else:
                response = await self.client.request(
                    injected_request.method,
                    injected_request.url,
                    content=injected_request.body,
                    headers=headers
                )

            response.raise_for_status()

            # Try to parse JSON response
            try:
                data = response.json()
                return self._extract_response(data)
            except json.JSONDecodeError:
                return response.text

        except httpx.HTTPStatusError as e:
            raise ConnectionError(f"HTTP {e.response.status_code}: {e.response.text[:200]}")
        except Exception as e:
            raise ConnectionError(f"Request failed: {str(e)}")

    def _extract_response(self, data: Any) -> str:
        """Extract response text from API response"""
        if not self.response_path:
            # Try common response paths
            common_paths = [
                'choices.0.message.content',  # OpenAI
                'content.0.text',              # Anthropic
                'message.content',             # Ollama
                'response',                    # Generic
                'text',                        # Simple
                'output',                      # Alternative
            ]
            for path in common_paths:
                try:
                    result = self._navigate_path(data, path)
                    if result:
                        return str(result)
                except (KeyError, IndexError, TypeError):
                    continue
            # Return full response as string if no path matches
            return json.dumps(data) if isinstance(data, dict) else str(data)

        return str(self._navigate_path(data, self.response_path))

    def _navigate_path(self, data: Any, path: str) -> Any:
        """Navigate nested path in response data"""
        result = data
        for key in path.split('.'):
            if key.isdigit():
                result = result[int(key)]
            else:
                result = result.get(key, '')
            if not result:
                break
        return result

    async def close(self) -> None:
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None


# Type hint import for RequestConnector
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from aix.core.request_parser import ParsedRequest
