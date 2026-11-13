"""Synthetic public-client OAuth authority. Not a production identity provider."""

import base64
import hashlib
import re
import secrets
from threading import RLock
from time import monotonic

CALLBACKS = frozenset({"http://127.0.0.1/callback", "https://oauth.pstmn.io/v1/callback"})


class OAuthError(ValueError):
    pass


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")


class Authority:
    def __init__(self, resource, clock=monotonic):
        self.resource = resource
        self.clock = clock
        self._clients = {}
        self._codes = {}
        self._tokens = {}
        self._lock = RLock()

    def _prune(self):
        now = self.clock()
        self._codes = {k: v for k, v in self._codes.items() if v["expires"] > now}
        self._tokens = {k: v for k, v in self._tokens.items() if v["expires"] + 60 > now}

    def register(self, redirects):
        if not isinstance(redirects, list) or not redirects or any(not isinstance(r, str) or r not in CALLBACKS for r in redirects):
            raise OAuthError("invalid_redirect")
        with self._lock:
            if len(self._clients) >= 100:
                raise OAuthError("invalid_client")
            client = secrets.token_urlsafe(24)
            self._clients[client] = tuple(redirects)
            return client

    def authorize(self, params):
        with self._lock:
            self._prune()
            client = params.get("client_id")
            if client not in self._clients:
                raise OAuthError("invalid_client")
            if params.get("redirect_uri") not in self._clients[client]:
                raise OAuthError("invalid_redirect")
            if params.get("resource") != self.resource:
                raise OAuthError("resource_mismatch")
            if params.get("scope") not in {"mcp:echo", "mcp:connect"}:
                raise OAuthError("invalid_scope")
            if (params.get("response_type") != "code" or params.get("code_challenge_method") != "S256"
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", ""))
                    or not params.get("state") or len(params["state"]) > 256 or len(self._codes) >= 1000):
                raise OAuthError("malformed")
            code = secrets.token_urlsafe(32)
            self._codes[code] = {**params, "expires": self.clock() + 60}
            return code

    def exchange(self, params):
        with self._lock:
            self._prune()
            if params.get("grant_type") != "authorization_code":
                raise OAuthError("malformed")
            grant = self._codes.pop(params.get("code"), None)
            if grant is None:
                raise OAuthError("invalid_grant")
            for field, error in (("client_id", "invalid_client"), ("redirect_uri", "invalid_redirect"), ("resource", "resource_mismatch")):
                if params.get(field) != grant[field]:
                    raise OAuthError(error)
            verifier = params.get("code_verifier", "")
            if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or not secrets.compare_digest(challenge(verifier), grant["code_challenge"]):
                raise OAuthError("pkce_mismatch")
            if len(self._tokens) >= 1000:
                raise OAuthError("invalid_grant")
            token = secrets.token_urlsafe(32)
            self._tokens[token] = {"scope": grant["scope"], "expires": self.clock() + 60}
            return token

    def check(self, authorization):
        if not authorization:
            return "missing_authorization"
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator:
            return "invalid_token"
        with self._lock:
            grant = self._tokens.get(token)
            if grant is None:
                return "invalid_token"
            if grant["expires"] <= self.clock():
                return "expired_token"
            if grant["scope"] != "mcp:echo":
                return "insufficient_scope"
            return "ok"
