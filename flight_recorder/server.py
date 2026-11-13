"""Loopback HTTP fixture with synthetic consent and safe server-side evidence."""

import json
import re
from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit

from .oauth import Authority, OAuthError
from .trace import PATHS, Recorder

MAX_BODY = 16_384


def parameters(raw):
    parsed = parse_qs(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
    if any(len(values) != 1 for values in parsed.values()):
        raise ValueError("Repeated parameter")
    return {key: value[0] for key, value in parsed.items()}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Repeated JSON field")
        result[key] = value
    return result


def reject_nonfinite(_):
    raise ValueError("JSON numbers must be finite")


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        # BaseHTTPRequestHandler logs query strings containing OAuth codes/state.
        pass

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def reply(self, status, body, headers=None, reason=None):
        lab = self.server.lab
        if reason is not None and self.path_only in PATHS:
            try:
                lab.recorder.add(self.run, self.command, self.path_only, status, reason,
                                 bool(self.headers.get("Authorization")))
            except ValueError:
                # Saturation fails closed rather than serving an unrecorded success.
                status, body, headers = 503, {"error": "recorder_capacity"}, {}
        payload = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def read_body(self, form=False):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Chunked bodies unsupported")
        if len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("One length required")
        length = int(self.headers["Content-Length"])
        if not 0 <= length <= MAX_BODY:
            raise ValueError("Request body too large")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if content_type != ("application/x-www-form-urlencoded" if form else "application/json"):
            raise ValueError("Unexpected media type")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Truncated body")
        data = parameters(raw.decode("utf-8")) if form else json.loads(
            raw, object_pairs_hook=unique_object, parse_constant=reject_nonfinite)
        if not isinstance(data, dict):
            raise ValueError("Object required")
        return data

    def dispatch(self):
        lab = self.server.lab
        split = urlsplit(self.path)
        self.path_only = split.path
        self.run = self.headers.get("X-Recorder-Run", "desktop")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.run):
            return self.reply(400, {"error": "invalid_run"})
        if self.headers.get("Host") != lab.base.removeprefix("http://") or self.headers.get("Origin"):
            return self.reply(403, {"error": "loopback_only"})
        if self.path_only == "/recorder/timeline" and self.command == "GET" and not split.query:
            return self.reply(200, {"events": lab.recorder.events(self.run)})
        if self.path_only not in PATHS:
            return self.reply(404, {"error": "not_found"})
        try:
            if split.query and self.path_only != "/oauth/authorize":
                raise ValueError("Query not accepted")
            expected = "GET" if self.path_only.startswith("/.well-known/") or self.path_only == "/oauth/authorize" else "POST"
            if self.command != expected:
                return self.reply(405, {"error": "method_not_allowed"}, {"Allow": expected}, "method_not_allowed")
            if self.path_only.startswith("/.well-known/oauth-protected-resource"):
                return self.reply(200, {"resource": lab.base + "/mcp", "authorization_servers": [lab.base],
                                        "scopes_supported": ["mcp:echo"]}, reason="discovery")
            if self.path_only == "/.well-known/oauth-authorization-server":
                return self.reply(200, {"issuer": lab.base, "authorization_endpoint": lab.base + "/oauth/authorize",
                    "token_endpoint": lab.base + "/oauth/token", "registration_endpoint": lab.base + "/oauth/register",
                    "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
                    "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
                    "scopes_supported": ["mcp:echo", "mcp:connect"]}, reason="discovery")
            if self.path_only == "/oauth/register":
                data = self.read_body()
                if data.get("token_endpoint_auth_method", "none") != "none":
                    raise OAuthError("invalid_client")
                client = lab.authority.register(data.get("redirect_uris"))
                return self.reply(201, {"client_id": client, "redirect_uris": data["redirect_uris"],
                    "token_endpoint_auth_method": "none", "grant_types": ["authorization_code"],
                    "response_types": ["code"]}, reason="registered")
            if self.path_only == "/oauth/authorize":
                data = parameters(split.query)
                code = lab.authority.authorize(data)
                return self.reply(302, None, {"Location": data["redirect_uri"] + "?" + urlencode({"code": code, "state": data["state"]})}, "authorized")
            if self.path_only == "/oauth/token":
                data = self.read_body(form=True)
                token = lab.authority.exchange(data)
                return self.reply(200, {"access_token": token, "token_type": "Bearer", "expires_in": 60}, reason="token_issued")
            if self.path_only == "/mcp":
                authorization = self.headers.get("Authorization", "")
                result = lab.authority.check(authorization)
                if result != "ok":
                    status = 403 if result == "insufficient_scope" else 401
                    reason = result
                    if result == "missing_authorization" and not any(e["reason"] == "token_issued" for e in lab.recorder.events(self.run)):
                        reason = "challenge"
                    error = "insufficient_scope" if status == 403 else "invalid_token"
                    challenge = f'Bearer realm="OAuth", resource_metadata="{lab.base}/.well-known/oauth-protected-resource/mcp", error="{error}", scope="mcp:echo"'
                    return self.reply(status, {"error": error}, {"WWW-Authenticate": challenge}, reason)
                from .mcp import handle
                status, body, reason = handle(self.read_body())
                return self.reply(status, body, reason=reason)
        except OAuthError as error:
            reason = str(error)
            public = "invalid_grant" if self.path_only == "/oauth/token" else "invalid_request"
            return self.reply(400, {"error": public}, reason=reason)
        except (ValueError, UnicodeError, RecursionError):
            return self.reply(400, {"error": "invalid_request"}, reason="malformed")


class LabServer(AbstractContextManager):
    def __init__(self, port=0, clock=None):
        self.recorder = Recorder()
        self.http = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.http.daemon_threads = True
        self.http.lab = self
        self.base = f"http://127.0.0.1:{self.http.server_port}"
        self.authority = Authority(self.base + "/mcp", **({"clock": clock} if clock is not None else {}))
        self.thread = Thread(target=self.http.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.http.shutdown()
        self.thread.join(timeout=6)
        self.http.server_close()
