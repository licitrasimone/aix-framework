"""
AIX Request Parser

Parses Burp Suite style HTTP request files and extracts components
for use with the AIX framework.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus


@dataclass
class ParsedRequest:
    """Represents a parsed HTTP request"""
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    body_json: dict[str, Any] | None = None
    injection_param: str | None = None

    @property
    def host(self) -> str:
        """Extract host from URL or headers"""
        if 'Host' in self.headers:
            return self.headers['Host']
        # Parse from URL
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        return parsed.netloc

    @property
    def content_type(self) -> str | None:
        """Get content type from headers"""
        for key, value in self.headers.items():
            if key.lower() == 'content-type':
                return value.split(';')[0].strip()
        return None

    @property
    def is_json(self) -> bool:
        """Check if body is JSON"""
        return self.content_type == 'application/json' and self.body_json is not None


class RequestParseError(Exception):
    """Raised when request parsing fails"""
    pass


class RequestParser:
    """Parser for Burp Suite style HTTP request files"""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise RequestParseError(f"Request file not found: {filepath}")

    def parse(self, injection_param: str | None = None) -> ParsedRequest:
        """Parse the request file and return a ParsedRequest object"""
        content = self.filepath.read_text(encoding='utf-8')
        return self.parse_raw(content, injection_param)

    @staticmethod
    def parse_raw(content: str, injection_param: str | None = None) -> ParsedRequest:
        """Parse raw HTTP request content"""
        lines = content.strip().split('\n')
        if not lines:
            raise RequestParseError("Empty request file")

        # Parse request line (e.g., "POST /v1/chat/completions HTTP/1.1")
        request_line = lines[0].strip()
        method, path, protocol = RequestParser._parse_request_line(request_line)

        # Parse headers
        headers = {}
        body_start_idx = len(lines)

        for i, line in enumerate(lines[1:], start=1):
            line = line.strip()
            if line == '':
                body_start_idx = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Parse body
        body = None
        body_json = None
        if body_start_idx < len(lines):
            body = '\n'.join(lines[body_start_idx:]).strip()
            if body:
                # Try to parse as JSON
                try:
                    body_json = json.loads(body)
                except json.JSONDecodeError:
                    pass

        # Construct full URL
        host = headers.get('Host', 'localhost')
        scheme = 'https' if '443' in host else 'http'
        url = f"{scheme}://{host}{path}"

        return ParsedRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            body_json=body_json,
            injection_param=injection_param
        )

    @staticmethod
    def _parse_request_line(line: str) -> tuple:
        """Parse the HTTP request line"""
        parts = line.split()
        if len(parts) < 2:
            raise RequestParseError(f"Invalid request line: {line}")

        method = parts[0].upper()
        path = parts[1]
        protocol = parts[2] if len(parts) > 2 else 'HTTP/1.1'

        return method, path, protocol


def set_nested_value(obj: Any, path: str, value: Any) -> Any:
    """
    Set a value at a nested path in a dict/list structure.

    Supports paths like:
    - "message" -> obj["message"]
    - "messages[0].content" -> obj["messages"][0]["content"]
    - "data.user.name" -> obj["data"]["user"]["name"]

    Returns a copy with the value set.
    """
    import copy
    obj = copy.deepcopy(obj)

    # Parse path into components
    components = _parse_path(path)

    # Navigate to parent and set value
    current = obj
    for i, comp in enumerate(components[:-1]):
        if isinstance(comp, int):
            current = current[comp]
        else:
            current = current[comp]

    # Set final value
    final_key = components[-1]
    if isinstance(final_key, int):
        current[final_key] = value
    else:
        current[final_key] = value

    return obj


def get_nested_value(obj: Any, path: str) -> Any:
    """
    Get a value at a nested path in a dict/list structure.

    Supports paths like:
    - "message" -> obj["message"]
    - "messages[0].content" -> obj["messages"][0]["content"]
    """
    components = _parse_path(path)

    current = obj
    for comp in components:
        if isinstance(comp, int):
            current = current[comp]
        else:
            current = current[comp]

    return current


def _parse_path(path: str) -> list[Any]:
    """
    Parse a path string into components.

    "messages[0].content" -> ["messages", 0, "content"]
    """
    components = []

    # Split by dots, but handle array indices
    pattern = r'([^\.\[\]]+)|\[(\d+)\]'
    matches = re.findall(pattern, path)

    for match in matches:
        if match[0]:  # String key
            components.append(match[0])
        elif match[1]:  # Array index
            components.append(int(match[1]))

    return components


def inject_payload(request: ParsedRequest, payload: str) -> ParsedRequest:
    """
    Create a new ParsedRequest with the payload injected at the specified parameter.

    Args:
        request: The original parsed request
        payload: The payload to inject

    Returns:
        New ParsedRequest with payload injected
    """
    import copy

    if not request.injection_param:
        raise RequestParseError("No injection parameter specified")

    new_request = copy.deepcopy(request)

    if request.is_json and request.body_json:
        # Inject into JSON body
        new_request.body_json = set_nested_value(
            request.body_json,
            request.injection_param,
            payload
        )
        new_request.body = json.dumps(new_request.body_json)
    elif request.body:
        # Handle form-urlencoded body (key=value&key2=value2)
        # We need to replace the value of the specified parameter

        # Regex to match: (^|&)param=([^&]*)
        # We want to replace group 2 with the payload
        param = re.escape(request.injection_param)
        pattern = r'(^|&)' + param + r'=([^&]*)'

        if re.search(pattern, request.body):
            # Replace logic: keep the delimiter and key, replace value with payload
            # We use lambda to handle the replacement safely since payload might have backslashes
            # URL-encode payload for form-urlencoded bodies
            encoded_payload = quote_plus(payload)
            new_request.body = re.sub(
                pattern,
                lambda m: f"{m.group(1)}{request.injection_param}={encoded_payload}",
                request.body
            )
        else:
            # Fallback: if param not found as key=value, try naive replacement (placeholder style)
            # This covers cases where user just put "MARKER" in the body
            if request.injection_param in request.body:
                 # If it looks like a placeholder, maybe don't encode?
                 # But if it's in a form body, it probably should be.
                 # Let's check if the body looks like url-encoded (has & or =)
                 if '&' in request.body or '=' in request.body:
                     new_request.body = request.body.replace(request.injection_param, quote_plus(payload))
                 else:
                     new_request.body = request.body.replace(request.injection_param, payload)
            else:
                 # If explicit parameter was requested but not found even as text
                 # effectively append it? Or just error?
                 # For now, let's append it to be helpful for form-data
                 encoded_payload = quote_plus(payload)
                 if new_request.body:
                     new_request.body += f"&{request.injection_param}={encoded_payload}"
                 else:
                     new_request.body = f"{request.injection_param}={encoded_payload}"
    else:
        raise RequestParseError("No body to inject payload into")

    return new_request


def load_request(filepath: str, injection_param: str | None = None) -> ParsedRequest:
    """
    Convenience function to load and parse a request file.

    Args:
        filepath: Path to the request file
        injection_param: Parameter path for payload injection

    Returns:
        ParsedRequest object
    """
    parser = RequestParser(filepath)
    return parser.parse(injection_param)


__all__ = [
    'ParsedRequest',
    'RequestParser',
    'RequestParseError',
    'load_request',
    'inject_payload',
    'set_nested_value',
    'get_nested_value',
]
