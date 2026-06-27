#!/usr/bin/env python3
"""
Socket.IO → HTTP bridge for aix.

Handles the full Engine.IO v4 handshake (polling → WebSocket upgrade)
so that aix modules can test Socket.IO targets normally:

    aix inject http://localhost:8765 --response-path output [other flags]

Usage:
    python socketio_bridge.py \
        --base-url https://your-target.example.com \
        --user-email your.email@domain.com \
        --location https://frontend.your-target.example.com/ \
        [--sio-path /socket.io/]          (default: /socket.io/) \
        [--cookie "session=abc;token=xyz"] \
        [--header "Authorization:Bearer token"] \
        [--port 8765]
"""

import argparse
import asyncio
import json
import logging
import ssl
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.request import Request

import websockets

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("bridge")


def set_debug():
    logging.getLogger().setLevel(logging.DEBUG)
    log.debug("Debug logging enabled — all raw frames will be printed")


class SocketIOBridge:
    def __init__(self, base_url: str, user_email: str, location: str,
                 sio_path: str = "/socket.io/",
                 cookies: str = "", headers: str = "", timeout: int = 60,
                 proxy: str = ""):
        self.base_url = base_url.rstrip("/")
        self.user_email = user_email
        self.location = location
        self.sio_path = sio_path
        self.cookies = cookies
        self.headers = headers
        self.timeout = timeout
        self.proxy = proxy  # e.g. "http://127.0.0.1:8080"
        self._eio_version = 4  # detected at handshake time
        self._thread_id = ""  # captured from server on first response, reused after

        # Derive HTTP and WS base URLs
        if self.base_url.startswith("https://"):
            self._http_base = self.base_url
            self._ws_base = "wss://" + self.base_url[len("https://"):]
        elif self.base_url.startswith("http://"):
            self._http_base = self.base_url
            self._ws_base = "ws://" + self.base_url[len("http://"):]
        elif self.base_url.startswith("wss://"):
            self._ws_base = self.base_url
            self._http_base = "https://" + self.base_url[len("wss://"):]
        else:
            self._ws_base = "ws://" + self.base_url[len("ws://"):]
            self._http_base = "http://" + self.base_url[len("ws://"):]

    def _extra_headers(self) -> dict:
        h = {}
        if self.cookies:
            pairs = [c.strip() for c in self.cookies.split(";") if "=" in c]
            h["Cookie"] = "; ".join(pairs)
        if self.headers:
            for item in self.headers.split(";"):
                if ":" in item:
                    k, v = item.split(":", 1)
                    h[k.strip()] = v.strip()
        return h

    def _get_sid(self) -> str:
        """Phase 1: HTTP polling handshake to obtain Engine.IO sid."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Build opener — route through proxy if set (Burp = http://127.0.0.1:8080)
        if self.proxy:
            log.info(f"  HTTP polling via proxy: {self.proxy}")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}),
                urllib.request.HTTPSHandler(context=ctx),
            )
        else:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        # Try EIO=4 first, fall back to EIO=3
        for eio in (4, 3):
            poll_url = f"{self._http_base}{self.sio_path}?EIO={eio}&transport=polling"
            log.info(f"Polling handshake EIO={eio}: GET {poll_url}")
            req = Request(poll_url)
            for k, v in self._extra_headers().items():
                req.add_header(k, v)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read().decode()
                log.debug(f"Polling response: {body[:300]}")
                json_start = body.find("{")
                if json_start == -1:
                    raise RuntimeError(f"No JSON in polling response: {body[:100]}")
                data = json.loads(body[json_start:])
                sid = data.get("sid")
                if not sid:
                    raise RuntimeError(f"No sid in polling response: {body[:100]}")
                log.info(f"Got sid (EIO={eio}): {sid}")
                self._eio_version = eio
                return sid
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                log.error(
                    f"Polling handshake EIO={eio} failed: HTTP {e.code} {e.reason}\n"
                    f"  URL: {poll_url}\n"
                    f"  Response body: {body[:300]}\n"
                    f"  Hint: check --sio-path, --cookie, and that the target is reachable"
                )
                if eio == 3:
                    raise RuntimeError(
                        f"Polling handshake failed (tried EIO=4 and EIO=3). "
                        f"Last error: HTTP {e.code} — {body[:200]}"
                    )
        raise RuntimeError("Polling handshake failed (unreachable)")

    def _build_frame(self, payload: str) -> str:
        msg_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event = [
            "client_message",
            {
                "message": {
                    "threadId": self._thread_id,
                    "id": msg_id,
                    "name": self.user_email,
                    "type": "user_message",
                    "output": payload,
                    "createdAt": ts,
                    "metadata": {"location": self.location},
                },
                "fileReferences": [],
            },
        ]
        return "42" + json.dumps(event)

    async def send(self, payload: str) -> str:
        """Full Socket.IO send: polling handshake → WS upgrade → send → collect."""
        log.info(f"[1/5] Polling handshake — getting sid ...")
        sid = await asyncio.get_event_loop().run_in_executor(None, self._get_sid)

        ws_url = f"{self._ws_base}{self.sio_path}?EIO={self._eio_version}&transport=websocket&sid={sid}"
        log.info(f"[2/5] WS upgrade → {ws_url}")

        ssl_ctx = None
        if ws_url.startswith("wss://"):
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        ai_output = ""

        # Route WebSocket through proxy (Burp) if set
        ws_kwargs = dict(
            additional_headers=self._extra_headers(),
            ssl=ssl_ctx,
            open_timeout=self.timeout,
            close_timeout=self.timeout,
        )
        if self.proxy:
            try:
                from python_socks.async_.asyncio import Proxy as SocksProxy
            except ImportError:
                raise RuntimeError(
                    "python-socks is required for WebSocket proxy support.\n"
                    "Install with: pip install python-socks"
                )
            from urllib.parse import urlparse
            parsed = urlparse(ws_url)
            host = parsed.hostname
            port = parsed.port or (443 if ws_url.startswith("wss://") else 80)
            log.info(f"  WS connecting via proxy {self.proxy} → {host}:{port}")
            proxy_conn = SocksProxy.from_url(self.proxy)
            sock = await proxy_conn.connect(dest_host=host, dest_port=port, timeout=self.timeout)
            ws_kwargs["sock"] = sock
            ws_kwargs["server_hostname"] = host

        async with websockets.connect(ws_url, **ws_kwargs) as ws:
            # Engine.IO upgrade probe
            await ws.send("2probe")
            log.debug("  → sent: 2probe")
            raw = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
            log.debug(f"  ← recv: {raw}")
            if raw != "3probe":
                raise RuntimeError(f"Unexpected probe response (expected 3probe): {raw}")
            await ws.send("5")
            log.debug("  → sent: 5 (upgrade confirmed)")
            log.info("[3/5] WS upgrade complete")

            # Socket.IO namespace connect
            await ws.send("40")
            log.debug("  → sent: 40 (namespace connect)")
            # Wait up to 3s for "40" confirmation; some servers (uvicorn/fastapi)
            # send NOOP "6" or nothing — treat that as implicit connect OK
            try:
                ns_deadline = asyncio.get_event_loop().time() + 3.0
                while asyncio.get_event_loop().time() < ns_deadline:
                    raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    log.debug(f"  ← recv: {raw[:120]}")
                    if raw == "2":
                        await ws.send("3")
                        log.debug("  → sent: 3 (pong)")
                        continue
                    if raw.startswith("40"):
                        log.info("[4/5] Namespace connected (confirmed)")
                        break
                    if raw.startswith("44"):
                        raise RuntimeError(f"Socket.IO namespace connect rejected: {raw}")
                    # 6 = NOOP or anything else → server connected implicitly
                    log.info(f"[4/5] Namespace connected (implicit, server sent: {raw[:20]})")
                    break
                else:
                    log.info("[4/5] Namespace connected (no confirmation from server, proceeding)")
            except asyncio.TimeoutError:
                log.info("[4/5] Namespace connected (timeout waiting for confirm, proceeding)")

            # Wait for on_chat_start sequence to complete before sending
            log.info("[4b/5] Waiting for on_chat_start sequence...")
            seen_chat_start = False
            init_deadline = asyncio.get_event_loop().time() + 15.0
            while asyncio.get_event_loop().time() < init_deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                except asyncio.TimeoutError:
                    log.info("  [init] 2s silence — proceeding")
                    break
                if raw == "2":
                    await ws.send("3")
                    continue
                if not raw.startswith("42"):
                    log.debug(f"  [init] non-event: {raw[:30]}")
                    continue
                try:
                    parsed = json.loads(raw[2:])
                    ev = parsed[0]
                    ed = parsed[1] if len(parsed) > 1 else {}
                except Exception:
                    continue
                log.info(f"  [init] ← {ev} name={ed.get('name','')} threadId={ed.get('threadId','')[:8]}")
                # capture threadId from on_chat_start
                tid = ed.get("threadId", "")
                if tid and not self._thread_id:
                    self._thread_id = tid
                    log.info(f"  [init] threadId captured: {tid}")
                if ev in ("new_message", "update_message") and ed.get("name") == "on_chat_start":
                    seen_chat_start = True
                if ev == "task_end" and seen_chat_start:
                    log.info("  [init] on_chat_start complete — ready to send")
                    break

            # Send payload
            frame = self._build_frame(payload)
            log.info(f"[5/5] Sending payload: {payload[:80]}")
            log.debug(f"  → frame: {frame[:200]}")
            await ws.send(frame)

            # Collect AI response until task_end or timeout
            events_seen = []
            deadline = asyncio.get_event_loop().time() + self.timeout
            while asyncio.get_event_loop().time() < deadline:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=min(5.0, remaining))
                except asyncio.TimeoutError:
                    log.debug("  (no frame in last 5s, still waiting...)")
                    continue

                if raw == "2":
                    await ws.send("3")
                    log.debug("  ← ping / → pong")
                    continue

                if not raw.startswith("42"):
                    log.debug(f"  ← (non-event frame): {raw[:80]}")
                    continue

                try:
                    parsed = json.loads(raw[2:])
                    event_name = parsed[0]
                    event_data = parsed[1] if len(parsed) > 1 else {}
                except Exception:
                    log.debug(f"  ← (unparseable frame): {raw[:80]}")
                    continue

                events_seen.append(event_name)
                msg_type = event_data.get("type", "")
                msg_id = event_data.get("id", "")[:8]
                out_preview = str(event_data.get("output", ""))[:60]
                log.info(f"  ← [{event_name}] type={msg_type} id={msg_id} output={out_preview!r}")

                # Capture threadId from any server event
                tid = event_data.get("threadId", "")
                if tid and not self._thread_id:
                    self._thread_id = tid
                    log.info(f"  threadId captured: {tid}")

                if event_name == "task_end":
                    log.info(f"  task_end — events seen: {events_seen}")
                    break

                if event_name in ("stream_start", "new_message", "update_message"):
                    if msg_type == "assistant_message":
                        out = event_data.get("output", "")
                        if out:
                            ai_output = out
                            log.info(f"  ✓ captured AI response ({len(out)} chars): {out[:120]}")

        return ai_output


def _extract_openai_content(data: dict) -> str:
    """Extract text from OpenAI-format body: messages[-1].content or messages[0].content."""
    msgs = data.get("messages")
    if not msgs or not isinstance(msgs, list):
        return ""
    # prefer last user message
    for msg in reversed(msgs):
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, list):  # vision format
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        return part.get("text", "")
            return str(content) if content else ""
    return str(msgs[-1].get("content", "")) if msgs else ""


# --- HTTP server ---

_bridge: SocketIOBridge = None
_loop: asyncio.AbstractEventLoop = None


class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info(f"HTTP {format % args}")

    def do_GET(self):
        """Health-check only at /. Return 404 for all other paths to prevent recon false positives."""
        if self.path != "/":
            self._respond(404, {"error": "not found"})
            return
        info = {
            "status": "ok",
            "target": f"{_bridge._http_base}{_bridge.sio_path}",
            "eio_version": _bridge._eio_version,
            "hint": "POST with JSON body {\"message\": \"<payload>\"} to send a test",
        }
        self._respond(200, info)

    def do_POST(self):
        if self.path != "/":
            self._respond(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        # Extract payload — support generic {"message":...}, OpenAI {"messages":[...]},
        # and any other single-field formats aix may send
        payload = (
            data.get("message")
            or data.get("query")
            or data.get("input")
            or data.get("prompt")
            or _extract_openai_content(data)
            or None
        )
        if not payload:
            log.warning(f"Could not extract payload from body: {str(data)[:120]}")
            self._respond(400, {"error": "no payload found", "received": str(data)[:200]})
            return

        try:
            future = asyncio.run_coroutine_threadsafe(_bridge.send(payload), _loop)
            result = future.result(timeout=_bridge.timeout + 10)
        except Exception as e:
            log.error(f"Bridge error: {e}")
            try:
                self._respond(500, {"error": str(e)})
            except Exception:
                pass
            return

        try:
            self._respond(200, {"output": result})
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            log.warning("aix closed the connection before response was sent (timeout on client side)")

    def _respond(self, status: int, body: dict):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def run_event_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


def main():
    parser = argparse.ArgumentParser(description="Socket.IO → HTTP bridge for aix")
    parser.add_argument("--base-url", required=True,
                        help="Base URL of the target, e.g. https://target.example.com")
    parser.add_argument("--user-email", required=True, help="Sender email identity")
    parser.add_argument("--location", required=True, help="Frontend URL (metadata.location)")
    parser.add_argument("--sio-path", default="/socket.io/",
                        help="Socket.IO mount path (default: /socket.io/)")
    parser.add_argument("--cookie", default="", help="Cookies: key=val;key2=val2")
    parser.add_argument("--header", default="", help="Headers: Key:Val;Key2:Val2")
    parser.add_argument("--port", type=int, default=8765, help="Local HTTP port (default 8765)")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds (default 120)")
    parser.add_argument("--proxy", default="", help="HTTP proxy for Burp interception, e.g. http://127.0.0.1:8080")
    parser.add_argument("--debug", action="store_true", help="Show all raw WS frames")
    parser.add_argument("--test", action="store_true", help="Send a test message at startup and exit")
    args = parser.parse_args()

    if args.debug:
        set_debug()

    global _bridge, _loop
    _bridge = SocketIOBridge(
        base_url=args.base_url,
        user_email=args.user_email,
        location=args.location,
        sio_path=args.sio_path,
        cookies=args.cookie,
        headers=args.header,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    _loop = asyncio.new_event_loop()
    t = Thread(target=run_event_loop, args=(_loop,), daemon=True)
    t.start()

    if args.test:
        log.info("=== TEST MODE — sending 'hello' to verify the full pipeline ===")
        try:
            future = asyncio.run_coroutine_threadsafe(_bridge.send("hello"), _loop)
            result = future.result(timeout=args.timeout + 10)
            if result:
                log.info(f"=== TEST PASSED — AI replied: {result[:200]} ===")
            else:
                log.warning("=== TEST WARNING — connected OK but got empty response ===")
        except Exception as e:
            log.error(f"=== TEST FAILED — {e} ===")
        return

    server = HTTPServer(("127.0.0.1", args.port), BridgeHandler)
    log.info(f"Bridge listening on http://127.0.0.1:{args.port}")
    log.info(f"Target: {args.base_url}{args.sio_path}")
    log.info(f"Run aix: aix inject http://127.0.0.1:{args.port} --response-path output --timeout 120")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopped.")


if __name__ == "__main__":
    main()
