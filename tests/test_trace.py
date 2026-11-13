import json

from flight_recorder.trace import Recorder, diagnose


def test_discovery_challenge_is_not_failure():
    recorder = Recorder()
    recorder.add("run", "POST", "/mcp", 401, "challenge", False)
    assert diagnose(recorder.events("run"))["reason"] == "incomplete"


def test_token_without_header_identifies_transport_boundary():
    recorder = Recorder()
    recorder.add("run", "POST", "/oauth/token", 200, "token_issued", False)
    recorder.add("run", "POST", "/mcp", 401, "missing_authorization", False)
    assert diagnose(recorder.events("run"))["reason"] == "missing_authorization"
    assert diagnose(recorder.events("run"))["boundary"] == "POST /mcp"


def test_runs_are_isolated_and_return_copies():
    recorder = Recorder()
    recorder.add("one", "POST", "/oauth/token", 200, "token_issued", False)
    events = recorder.events("one")
    events.clear()
    assert len(recorder.events("one")) == 1
    assert recorder.events("two") == []


def test_trace_rejects_unbounded_or_sensitive_fields():
    import pytest

    recorder = Recorder()
    for field in ("/mcp?access_token=secret", "/secret"):
        with pytest.raises(ValueError):
            recorder.add("run", "GET", field, 400, "malformed", False)
    with pytest.raises(ValueError):
        recorder.add("run", "POST", "/mcp", 401, "Bearer secret", True)
    assert "secret" not in json.dumps(recorder.events("run"))
