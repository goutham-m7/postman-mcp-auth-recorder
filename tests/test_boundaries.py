import http.client
import json
from concurrent.futures import ThreadPoolExecutor

from flight_recorder.server import LabServer, MAX_BODY
from flight_recorder.trace import Recorder
from tests.helpers import issue, request


def raw(base, body, headers=None):
    connection = http.client.HTTPConnection(base.removeprefix("http://"), timeout=5)
    try:
        connection.request("POST", "/oauth/register", body, {"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_overlong_malformed_and_deep_json_return_bounded_errors():
    with LabServer() as lab:
        for body in (b"{invalid", b"x" * (MAX_BODY + 1), b"[" * 1200 + b"]" * 1200):
            assert raw(lab.base, body) == 400


def test_repeated_json_fields_and_nonfinite_numbers_are_rejected():
    with LabServer() as lab:
        for body in (b'{"redirect_uris":[],"redirect_uris":["http://127.0.0.1/callback"]}',
                     b'{"redirect_uris":["http://127.0.0.1/callback"],"value":NaN}'):
            assert raw(lab.base, body) == 400


def test_concurrent_code_exchange_can_issue_only_one_token():
    with LabServer() as lab:
        data = issue(lab.base)
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(lambda _: request(lab.base, "POST", "/oauth/token", data, form=True)[0], range(4)))
        assert sorted(statuses) == [200, 400, 400, 400]
        assert sum(e["reason"] == "token_issued" for e in lab.recorder.events("test")) == 1


def test_recorder_snapshot_does_not_allow_mutating_prior_event():
    recorder = Recorder()
    recorder.add("r", "GET", "/.well-known/oauth-authorization-server", 200, "discovery", False)
    events = recorder.events("r")
    events[0]["reason"] = "tampered"
    assert recorder.events("r")[0]["reason"] == "discovery"


def test_capacity_fails_closed_instead_of_silent_unrecorded_success():
    with LabServer() as lab:
        for _ in range(1000):
            lab.recorder.add("test", "GET", "/.well-known/oauth-authorization-server", 200, "discovery", False)
        status, _, body = request(lab.base, "GET", "/.well-known/oauth-authorization-server")
        assert status == 503
        assert body == {"error": "recorder_capacity"}
