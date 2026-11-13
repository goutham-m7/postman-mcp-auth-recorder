"""Real HTTP replays. Only consent and the expiry clock are synthetic."""

import json
import re
import secrets
from time import monotonic, perf_counter
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .mcp import ECHO, INITIALIZE
from .oauth import challenge
from .server import LabServer
from .trace import diagnose

CASES = {
    "valid": ("pass", None),
    "missing_bearer": ("missing_authorization", "POST /mcp"),
    "invalid_bearer": ("invalid_token", "POST /mcp"),
    "expired_token": ("expired_token", "POST /mcp"),
    "insufficient_scope": ("insufficient_scope", "POST /mcp"),
    "pkce_mismatch": ("pkce_mismatch", "POST /oauth/token"),
    "resource_mismatch": ("resource_mismatch", "POST /oauth/token"),
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Capture callback parameters, never follow them to an external host.
        return None


class Wire:
    def __init__(self, base, run):
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", base):
            raise ValueError("Only loopback fixture URLs are accepted")
        self.base, self.run = base, run
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.failure_received = None

    def send(self, method, path, data=None, authorization=None, form=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Relative fixture path required")
        headers = {"X-Recorder-Run": self.run, "Accept": "application/json, text/event-stream"}
        if authorization is not None:
            headers["Authorization"] = authorization
        body = None
        if data is not None:
            body = (urlencode(data) if form else json.dumps(data)).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        request = Request(self.base + path, body, headers, method=method)
        try:
            response = self.opener.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            if response.status >= 400:
                self.failure_received = perf_counter()
            return response.status, response.headers, json.loads(raw) if raw else None


def require(actual, expected, step):
    if actual != expected:
        raise RuntimeError(f"Unexpected HTTP status at {step}: expected {expected}, got {actual}")


def run_case(case):
    if case not in CASES:
        raise ValueError("Unknown case")
    offset = [0.0]
    with LabServer(clock=lambda: monotonic() + offset[0]) as lab:
        wire = Wire(lab.base, case)
        status, headers, _ = wire.send("POST", "/mcp", INITIALIZE)
        require(status, 401, "anonymous discovery probe")
        match = re.search(r'resource_metadata="([^"]+)"', headers["WWW-Authenticate"])
        if match is None or not match[1].startswith(lab.base + "/"):
            raise RuntimeError("Invalid discovery challenge")
        status, _, metadata = wire.send("GET", match[1][len(lab.base):])
        require(status, 200, "resource discovery")
        if metadata["resource"] != lab.base + "/mcp" or metadata["authorization_servers"] != [lab.base]:
            raise RuntimeError("Unexpected resource metadata")
        status, _, metadata = wire.send("GET", "/.well-known/oauth-authorization-server")
        require(status, 200, "authorization discovery")
        if metadata["issuer"] != lab.base:
            raise RuntimeError("Unexpected issuer")
        status, _, client = wire.send("POST", "/oauth/register", {
            "redirect_uris": ["http://127.0.0.1/callback"], "token_endpoint_auth_method": "none"})
        require(status, 201, "registration")
        verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
        sensitive = {verifier, state, client["client_id"]}
        params = {"client_id": client["client_id"], "redirect_uri": "http://127.0.0.1/callback",
                  "response_type": "code", "resource": lab.base + "/mcp", "scope": "mcp:connect" if case == "insufficient_scope" else "mcp:echo",
                  "state": state, "code_challenge_method": "S256", "code_challenge": challenge(verifier)}
        status, headers, _ = wire.send("GET", "/oauth/authorize?" + urlencode(params))
        require(status, 302, "authorization")
        callback = urlsplit(headers["Location"])
        if callback.scheme + "://" + callback.netloc + callback.path != params["redirect_uri"]:
            raise RuntimeError("Wrong callback target")
        values = parse_qs(callback.query)
        if values.get("state") != [state]:
            raise RuntimeError("OAuth state mismatch")
        code = values["code"][0]
        sensitive.add(code)
        data = {"client_id": client["client_id"], "redirect_uri": params["redirect_uri"],
                "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                "resource": params["resource"]}
        if case == "pkce_mismatch":
            data["code_verifier"] = "b" * 43
        if case == "resource_mismatch":
            data["resource"] = lab.base + "/wrong-resource"
        status, _, token = wire.send("POST", "/oauth/token", data, form=True)
        require(status, 400 if case in {"pkce_mismatch", "resource_mismatch"} else 200, "token exchange")
        if status == 200:
            sensitive.add(token["access_token"])
            authorization = "Bearer " + token["access_token"]
            if case == "missing_bearer":
                authorization = None
            if case == "invalid_bearer":
                invalid = secrets.token_urlsafe(32)
                sensitive.add(invalid)
                authorization = "Bearer " + invalid
            if case == "expired_token":
                offset[0] += 61
            status, _, _ = wire.send("POST", "/mcp", INITIALIZE, authorization)
            require(status, 200 if case == "valid" else 403 if case == "insufficient_scope" else 401, "post-token initialize")
            if case == "valid":
                require(wire.send("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, authorization)[0], 202, "initialized notification")
                require(wire.send("POST", "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, authorization)[0], 200, "tool discovery")
                status, _, echoed = wire.send("POST", "/mcp", ECHO, authorization)
                require(status, 200, "echo")
                if echoed["result"]["content"] != [{"type": "text", "text": "synthetic hello"}]:
                    raise RuntimeError("Echo did not return the expected synthetic payload")
        events = lab.recorder.events(case)
        diagnosis = diagnose(events)
        latency = round((perf_counter() - wire.failure_received) * 1000, 3) if case != "valid" else None
        expected = CASES[case]
        return {"case": case, "events": events, "diagnosis": diagnosis,
                "matches_expectation": (diagnosis["reason"], diagnosis["boundary"]) == expected,
                "failure_to_diagnosis_ms": latency}, sensitive
