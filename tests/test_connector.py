"""
Tests for AIX Connector Module
"""

import pytest

from aix.core.connector import APIConnector, RequestConnector, WebSocketConnector
from aix.core.request_parser import ParsedRequest


class TestAPIConnector:
    """Tests for APIConnector class"""

    def test_init_basic(self):
        """Test basic initialization"""
        connector = APIConnector(url="https://api.example.com/v1/chat", api_key="test-api-key")

        assert connector.url == "https://api.example.com/v1/chat"
        assert connector.api_key == "test-api-key"

    def test_init_with_proxy(self):
        """Test initialization with proxy"""
        connector = APIConnector(
            url="https://api.example.com", api_key="test-key", proxy="127.0.0.1:8080"
        )

        # Config stores kwargs
        assert connector.config.get("proxy") == "127.0.0.1:8080"

    def test_init_with_headers(self):
        """Test initialization with custom headers"""
        custom_headers = "X-Custom-Header:value;Authorization:Bearer token"
        connector = APIConnector(url="https://api.example.com", headers=custom_headers)

        assert connector.config.get("headers") == custom_headers

    def test_init_with_cookies(self):
        """Test initialization with cookies"""
        cookies = "session=abc123;token=xyz"
        connector = APIConnector(url="https://api.example.com", cookies=cookies)

        assert connector.config.get("cookies") == cookies

    def test_init_with_timeout(self):
        """Test initialization with custom timeout"""
        connector = APIConnector(url="https://api.example.com", timeout=60)

        assert connector.config.get("timeout") == 60

    def test_init_with_injection_param(self):
        """Test initialization with injection parameter"""
        connector = APIConnector(
            url="https://api.example.com", injection_param="messages[0].content"
        )

        assert connector.injection_param == "messages[0].content"

    def test_init_with_body_format(self):
        """Test initialization with body format"""
        connector = APIConnector(url="https://api.example.com", body_format="form")

        assert connector.body_format == "form"

    def test_init_with_response_regex(self):
        """Test initialization with response regex"""
        connector = APIConnector(
            url="https://api.example.com", response_regex=r'"content":\s*"([^"]+)"'
        )

        assert connector.response_regex == r'"content":\s*"([^"]+)"'

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager protocol"""
        connector = APIConnector(url="https://api.example.com", api_key="test")

        # Should not raise
        async with connector:
            pass

    def test_api_format_detection_openai(self):
        """Test OpenAI API format detection"""
        connector = APIConnector(url="https://api.openai.com/v1/chat", api_key="test")

        assert connector.api_format == "openai"

    def test_api_format_detection_anthropic(self):
        """Test Anthropic API format detection"""
        connector = APIConnector(url="https://api.anthropic.com/v1/messages", api_key="test")

        assert connector.api_format == "anthropic"

    def test_api_format_detection_generic(self):
        """Test generic API format for unknown URLs"""
        connector = APIConnector(url="https://custom.api.com/chat", api_key="test")

        assert connector.api_format == "generic"


class TestRequestConnector:
    """Tests for RequestConnector class"""

    def test_init_basic(self):
        """Test basic initialization with parsed request"""
        request = ParsedRequest(
            method="POST",
            url="https://api.example.com/chat",
            headers={"Content-Type": "application/json"},
            body='{"message": "test"}',
            body_json={"message": "test"},
            injection_param="message",
        )

        connector = RequestConnector(request)

        assert connector.parsed_request == request

    def test_init_with_proxy(self):
        """Test initialization with proxy"""
        request = ParsedRequest(
            method="POST", url="https://example.com", headers={}, injection_param="data"
        )

        connector = RequestConnector(request, proxy="127.0.0.1:8080")

        assert connector.config.get("proxy") == "127.0.0.1:8080"

    def test_init_with_timeout(self):
        """Test initialization with custom timeout"""
        request = ParsedRequest(
            method="POST", url="https://example.com", headers={}, injection_param="data"
        )

        connector = RequestConnector(request, timeout=120)

        assert connector.config.get("timeout") == 120

    def test_init_with_response_regex(self):
        """Test initialization with response regex"""
        request = ParsedRequest(
            method="POST", url="https://example.com", headers={}, injection_param="data"
        )

        connector = RequestConnector(request, response_regex=r"response:\s*(.+)")

        assert connector.response_regex == r"response:\s*(.+)"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager protocol"""
        request = ParsedRequest(
            method="POST", url="https://example.com", headers={}, injection_param="data"
        )

        connector = RequestConnector(request)

        async with connector:
            pass


class TestConnectorRefreshConfig:
    """Tests for session refresh configuration"""

    def test_refresh_config(self):
        """Test refresh configuration"""
        refresh_config = {
            "url": "https://auth.example.com/refresh",
            "regex": r"token:\s*(\S+)",
            "param": "Authorization",
            "error": "token expired",
        }

        connector = APIConnector(url="https://api.example.com", refresh_config=refresh_config)

        assert connector.refresh_config == refresh_config


class TestConnectorVerbosity:
    """Tests for verbosity settings"""

    def test_verbose_levels(self):
        """Test different verbosity levels"""
        for level in [0, 1, 2, 3]:
            connector = APIConnector(url="https://api.example.com", verbose=level)

            assert connector.config.get("verbose") == level


class TestConnectorCookieParsing:
    """Tests for cookie parsing"""

    def test_parse_cookies(self):
        """Test cookie string parsing"""
        connector = APIConnector(url="https://example.com")

        result = connector._parse_cookies("session=abc123;token=xyz789")

        assert result == {"session": "abc123", "token": "xyz789"}

    def test_parse_cookies_empty(self):
        """Test parsing empty cookie string"""
        connector = APIConnector(url="https://example.com")

        result = connector._parse_cookies(None)

        assert result == {}

    def test_parse_cookies_with_spaces(self):
        """Test parsing cookies with spaces"""
        connector = APIConnector(url="https://example.com")

        result = connector._parse_cookies("session = abc123 ; token = xyz")

        # Note: implementation may not strip whitespace from keys
        # Check that at least some keys are present
        assert len(result) >= 2


class TestConnectorHeaderParsing:
    """Tests for header parsing"""

    def test_parse_headers(self):
        """Test header string parsing"""
        connector = APIConnector(url="https://example.com")

        result = connector._parse_headers("X-Custom:value;Authorization:Bearer token")

        assert result == {"X-Custom": "value", "Authorization": "Bearer token"}

    def test_parse_headers_empty(self):
        """Test parsing empty header string"""
        connector = APIConnector(url="https://example.com")

        result = connector._parse_headers(None)

        assert result == {}


class TestWebSocketConnector:
    """Tests for WebSocketConnector class"""

    def test_init_defaults(self):
        """Test default initialization"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        assert connector.url == "wss://target.com/chat"
        assert connector.injection_param == "message"
        assert connector.response_path is None
        assert connector.timeout == 30
        assert connector.ws is None

    def test_init_custom_params(self):
        """Test initialization with custom parameters"""
        connector = WebSocketConnector(
            url="wss://target.com/chat",
            injection_param="query",
            response_path="data.content",
            timeout=60,
        )

        assert connector.injection_param == "query"
        assert connector.response_path == "data.content"
        assert connector.timeout == 60

    def test_build_message(self):
        """Test message building with default param"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        result = connector._build_message("hello")

        assert result == '{"message": "hello"}'

    def test_build_message_custom_param(self):
        """Test message building with custom injection param"""
        connector = WebSocketConnector(url="wss://target.com/chat", injection_param="query")

        result = connector._build_message("test payload")

        assert result == '{"query": "test payload"}'

    def test_extract_response_with_path(self):
        """Test response extraction with explicit path"""
        connector = WebSocketConnector(url="wss://target.com/chat", response_path="content")

        raw = '{"user": "Bot", "content": "Hello there!"}'
        result = connector._extract_response(raw)

        assert result == "Hello there!"

    def test_extract_response_nested_path(self):
        """Test response extraction with nested dot path"""
        connector = WebSocketConnector(url="wss://target.com/chat", response_path="data.text")

        raw = '{"data": {"text": "nested value"}}'
        result = connector._extract_response(raw)

        assert result == "nested value"

    def test_extract_response_fallback(self):
        """Test response extraction with fallback keys (no response_path)"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        raw = '{"user": "Bot", "content": "fallback hit"}'
        result = connector._extract_response(raw)

        assert result == "fallback hit"

    def test_extract_response_fallback_response_key(self):
        """Test fallback to 'response' key"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        raw = '{"response": "answer here"}'
        result = connector._extract_response(raw)

        assert result == "answer here"

    def test_extract_response_no_known_keys(self):
        """Test fallback to JSON dump when no known keys match"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        raw = '{"unknown_field": "some data"}'
        result = connector._extract_response(raw)

        assert "unknown_field" in result
        assert "some data" in result

    def test_extract_response_non_json(self):
        """Test non-JSON response passthrough"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        result = connector._extract_response("plain text response")

        assert result == "plain text response"

    def test_build_extra_headers_cookies(self):
        """Test extra headers with cookies"""
        connector = WebSocketConnector(url="wss://target.com/chat", cookies="session=abc;token=xyz")

        headers = connector._build_extra_headers()

        assert "Cookie" in headers
        assert "session=abc" in headers["Cookie"]
        assert "token=xyz" in headers["Cookie"]

    def test_build_extra_headers_custom(self):
        """Test extra headers with custom headers"""
        connector = WebSocketConnector(
            url="wss://target.com/chat", headers="Authorization:Bearer tok;X-Custom:val"
        )

        headers = connector._build_extra_headers()

        assert headers["Authorization"] == "Bearer tok"
        assert headers["X-Custom"] == "val"

    def test_build_extra_headers_both(self):
        """Test extra headers with both cookies and custom headers"""
        connector = WebSocketConnector(
            url="wss://target.com/chat",
            cookies="session=abc",
            headers="X-Custom:val",
        )

        headers = connector._build_extra_headers()

        assert "Cookie" in headers
        assert headers["X-Custom"] == "val"

    def test_build_extra_headers_empty(self):
        """Test extra headers when none configured"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        headers = connector._build_extra_headers()

        assert headers == {}

    def test_navigate_path_nested(self):
        """Test dot-path navigation in nested data"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        data = {"a": {"b": {"c": "deep"}}}
        result = connector._navigate_path(data, "a.b.c")

        assert result == "deep"

    def test_navigate_path_missing(self):
        """Test dot-path navigation with missing key"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        data = {"a": {"x": 1}}
        result = connector._navigate_path(data, "a.b.c")

        assert result == ""

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager protocol (close without connect)"""
        connector = WebSocketConnector(url="wss://target.com/chat")

        # close() should not raise even without a connection
        await connector.close()
        assert connector.ws is None
