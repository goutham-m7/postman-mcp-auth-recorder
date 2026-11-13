"""Allowlisted evidence: never accept arbitrary request or response payloads."""

from dataclasses import asdict, dataclass
from threading import RLock
from time import monotonic

PATHS = frozenset({"/mcp", "/oauth/register", "/oauth/authorize", "/oauth/token",
                   "/.well-known/oauth-protected-resource",
                   "/.well-known/oauth-protected-resource/mcp",
                   "/.well-known/oauth-authorization-server"})
REASONS = frozenset({"challenge", "discovery", "registered", "authorized", "token_issued",
                     "missing_authorization", "invalid_token", "expired_token",
                     "insufficient_scope", "pkce_mismatch", "resource_mismatch",
                     "invalid_grant", "invalid_client", "invalid_redirect", "invalid_scope",
                     "malformed", "initialized", "notification", "tools_listed", "echo",
                     "rpc_error", "method_not_allowed", "unsupported_version"})


@dataclass(frozen=True)
class Event:
    sequence: int
    elapsed_ms: float
    method: str
    path: str
    status: int
    reason: str
    authorization_present: bool


class Recorder:
    def __init__(self):
        self._runs = {}
        self._lock = RLock()
        self._start = monotonic()

    def add(self, run, method, path, status, reason, authorization_present):
        if path not in PATHS or reason not in REASONS or method not in {"GET", "POST"}:
            raise ValueError("Only known protocol facts may enter the recorder")
        with self._lock:
            if run not in self._runs and len(self._runs) >= 100:
                raise ValueError("Run capacity reached; restart the local lab")
            events = self._runs.setdefault(run, [])
            if len(events) >= 1000:
                raise ValueError("Event capacity reached; restart the local lab")
            events.append(Event(len(events) + 1, round((monotonic() - self._start) * 1000, 3),
                                method, path, status, reason, bool(authorization_present)))

    def events(self, run):
        with self._lock:
            return [asdict(event) for event in self._runs.get(run, [])]


def diagnose(events):
    """First failed protocol boundary, ignoring the expected anonymous probe."""
    issued = False
    for event in events:
        if event["reason"] == "token_issued":
            issued = True
        if event["status"] >= 400 and event["reason"] != "challenge":
            return {"reason": event["reason"],
                    "boundary": f'{event["method"]} {event["path"]}',
                    "token_issued": issued, "detected_at_ms": event["elapsed_ms"]}
    return {"reason": "pass" if any(e["reason"] == "echo" for e in events) else "incomplete",
            "boundary": None, "token_issued": issued, "detected_at_ms": None}
