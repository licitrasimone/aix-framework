"""
Tests for AIX Request Parser Module
"""
import json
import tempfile
from pathlib import Path

import pytest

from aix.core.request_parser import (
    ParsedRequest,
    RequestParseError,
    RequestParser,
    get_nested_value,
    inject_payload,
    load_request,
    set_nested_value,
)


class TestParsedRequest:
    """Tests for ParsedRequest dataclass"""

    def test_basic_creation(self):
        """Test basic request creation"""
        request = ParsedRequest(
            method="POST",
            url="https://api.example.com/chat",
            headers={"Content-Type": "application/json"},
            body='{"message": "hello"}',
            body_json={"message": "hello"}
        )

        assert request.method == "POST"
        assert request.url == "https://api.example.com/chat"
        assert request.headers["Content-Type"] == "application/json"

    def test_host_from_headers(self):
        """Test host extraction from headers"""
        request = ParsedRequest(
            method="GET",
            url="https://api.example.com/test",
            headers={"Host": "api.example.com"}
        )

        assert request.host == "api.example.com"

    def test_host_from_url(self):
        """Test host extraction from URL when no Host header"""
        request = ParsedRequest(
            method="GET",
            url="https://api.example.com:8080/test",
            headers={}
        )

        assert request.host == "api.example.com:8080"

    def test_content_type(self):
        """Test content type extraction"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

        assert request.content_type == "application/json"

    def test_content_type_case_insensitive(self):
        """Test content type header is case insensitive"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"content-type": "application/json"}
        )

        assert request.content_type == "application/json"

    def test_is_json(self):
        """Test JSON detection"""
        json_request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/json"},
            body='{"key": "value"}',
            body_json={"key": "value"}
        )

        non_json_request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "text/plain"},
            body="plain text"
        )

        assert json_request.is_json is True
        assert non_json_request.is_json is False


class TestRequestParser:
    """Tests for RequestParser class"""

    def test_parse_simple_get(self):
        """Test parsing simple GET request"""
        content = """GET /api/test HTTP/1.1
Host: api.example.com
Accept: application/json

"""
        request = RequestParser.parse_raw(content)

        assert request.method == "GET"
        assert "api.example.com" in request.url
        assert "/api/test" in request.url
        assert request.headers["Host"] == "api.example.com"
        assert request.headers["Accept"] == "application/json"

    def test_parse_post_with_json_body(self):
        """Test parsing POST request with JSON body"""
        content = """POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
Content-Type: application/json
Authorization: Bearer sk-test

{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}"""

        request = RequestParser.parse_raw(content)

        assert request.method == "POST"
        assert "api.openai.com" in request.url
        assert "/v1/chat/completions" in request.url
        assert request.body_json is not None
        assert request.body_json["model"] == "gpt-4"
        assert request.body_json["messages"][0]["content"] == "Hello"

    def test_parse_with_injection_param(self):
        """Test parsing with injection parameter"""
        content = """POST /chat HTTP/1.1
Host: example.com
Content-Type: application/json

{"message": "test"}"""

        request = RequestParser.parse_raw(content, injection_param="message")

        assert request.injection_param == "message"

    def test_parse_http_scheme(self):
        """Test HTTP scheme detection (non-443 port)"""
        content = """GET /test HTTP/1.1
Host: example.com:8080

"""
        request = RequestParser.parse_raw(content)

        assert request.url == "http://example.com:8080/test"

    def test_parse_https_scheme(self):
        """Test HTTPS scheme detection (443 port)"""
        content = """GET /test HTTP/1.1
Host: example.com:443

"""
        request = RequestParser.parse_raw(content)

        assert request.url == "https://example.com:443/test"

    def test_parse_empty_request(self):
        """Test parsing empty request raises error"""
        with pytest.raises(RequestParseError):
            RequestParser.parse_raw("")

    def test_parse_invalid_request_line(self):
        """Test parsing invalid request line raises error"""
        with pytest.raises(RequestParseError, match="Invalid request line"):
            RequestParser.parse_raw("INVALID")

    def test_parse_file_not_found(self):
        """Test file not found raises error"""
        with pytest.raises(RequestParseError, match="not found"):
            RequestParser("/nonexistent/path/request.txt")

    def test_parse_form_urlencoded(self):
        """Test parsing form-urlencoded body"""
        content = """POST /submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=test&password=secret"""

        request = RequestParser.parse_raw(content)

        assert request.body == "username=test&password=secret"
        assert request.body_json is None  # Not JSON

    def test_load_request_function(self):
        """Test load_request convenience function"""
        content = """POST /api HTTP/1.1
Host: example.com

{"data": "test"}"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            filepath = f.name

        try:
            request = load_request(filepath, injection_param="data")

            assert request.method == "POST"
            assert request.injection_param == "data"
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestNestedValueOperations:
    """Tests for nested value get/set operations"""

    def test_set_simple_key(self):
        """Test setting simple key"""
        obj = {"message": "original"}
        result = set_nested_value(obj, "message", "new")

        assert result["message"] == "new"
        assert obj["message"] == "original"  # Original unchanged

    def test_set_nested_key(self):
        """Test setting nested key"""
        obj = {"data": {"user": {"name": "old"}}}
        result = set_nested_value(obj, "data.user.name", "new")

        assert result["data"]["user"]["name"] == "new"

    def test_set_array_index(self):
        """Test setting array index"""
        obj = {"items": ["a", "b", "c"]}
        result = set_nested_value(obj, "items[1]", "X")

        assert result["items"][1] == "X"

    def test_set_nested_array(self):
        """Test setting nested value in array"""
        obj = {"messages": [{"role": "user", "content": "hello"}]}
        result = set_nested_value(obj, "messages[0].content", "new content")

        assert result["messages"][0]["content"] == "new content"

    def test_get_simple_key(self):
        """Test getting simple key"""
        obj = {"message": "test"}
        assert get_nested_value(obj, "message") == "test"

    def test_get_nested_key(self):
        """Test getting nested key"""
        obj = {"data": {"user": {"name": "John"}}}
        assert get_nested_value(obj, "data.user.name") == "John"

    def test_get_array_index(self):
        """Test getting array index"""
        obj = {"items": ["a", "b", "c"]}
        assert get_nested_value(obj, "items[1]") == "b"

    def test_get_nested_array(self):
        """Test getting nested value in array"""
        obj = {"messages": [{"role": "user", "content": "hello"}]}
        assert get_nested_value(obj, "messages[0].content") == "hello"


class TestInjectPayload:
    """Tests for payload injection"""

    def test_inject_json_simple(self):
        """Test injecting into simple JSON"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/json"},
            body='{"message": "original"}',
            body_json={"message": "original"},
            injection_param="message"
        )

        result = inject_payload(request, "PAYLOAD")

        assert result.body_json["message"] == "PAYLOAD"
        assert json.loads(result.body)["message"] == "PAYLOAD"

    def test_inject_json_nested(self):
        """Test injecting into nested JSON"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/json"},
            body='{"messages": [{"role": "user", "content": "hello"}]}',
            body_json={"messages": [{"role": "user", "content": "hello"}]},
            injection_param="messages[0].content"
        )

        result = inject_payload(request, "INJECTED")

        assert result.body_json["messages"][0]["content"] == "INJECTED"

    def test_inject_form_urlencoded(self):
        """Test injecting into form-urlencoded body"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=test&message=original",
            injection_param="message"
        )

        result = inject_payload(request, "PAYLOAD")

        assert "message=PAYLOAD" in result.body
        assert "username=test" in result.body

    def test_inject_form_with_special_chars(self):
        """Test injecting payload with special characters"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="query=test",
            injection_param="query"
        )

        result = inject_payload(request, "test&inject=bad")

        # Should be URL-encoded
        assert "test%26inject%3Dbad" in result.body

    def test_inject_no_param_raises(self):
        """Test injection without param raises error"""
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={},
            body="test"
        )

        with pytest.raises(RequestParseError, match="No injection parameter"):
            inject_payload(request, "PAYLOAD")

    def test_inject_preserves_original(self):
        """Test injection doesn't modify original request"""
        original_body = {"message": "original"}
        request = ParsedRequest(
            method="POST",
            url="https://example.com",
            headers={"Content-Type": "application/json"},
            body=json.dumps(original_body),
            body_json=original_body,
            injection_param="message"
        )

        inject_payload(request, "MODIFIED")

        assert request.body_json["message"] == "original"
