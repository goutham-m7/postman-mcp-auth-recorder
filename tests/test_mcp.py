import pytest

from flight_recorder.server import LabServer
from tests.helpers import issue, request


@pytest.fixture
def connection():
    with LabServer() as lab:
        _, _, result = request(
            lab.base, "POST", "/oauth/token", issue(lab.base), form=True
        )
        yield lab, {"Authorization": "Bearer " + result["access_token"]}


def rpc(method, params, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def test_initialize_notification_list_and_echo_over_http(connection):
    lab, headers = connection
    status, _, result = request(
        lab.base,
        "POST",
        "/mcp",
        rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        ),
        headers,
    )
    assert status == 200
    assert result["result"]["protocolVersion"] == "2025-06-18"
    assert result["result"]["capabilities"] == {"tools": {}}
    status, _, _ = request(
        lab.base,
        "POST",
        "/mcp",
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers,
    )
    assert status == 202
    _, _, tools = request(lab.base, "POST", "/mcp", rpc("tools/list", {}), headers)
    assert tools["result"]["tools"][0]["name"] == "echo"
    _, _, result = request(
        lab.base,
        "POST",
        "/mcp",
        rpc("tools/call", {"name": "echo", "arguments": {"text": "synthetic hello"}}),
        headers,
    )
    assert result["result"]["content"] == [{"type": "text", "text": "synthetic hello"}]


@pytest.mark.parametrize(
    "arguments",
    [{}, {"text": 17}, {"text": "ok", "extra": "no"}, {"text": "x" * 1025}, []],
)
def test_echo_rejects_invalid_arguments(connection, arguments):
    lab, headers = connection
    _, _, body = request(
        lab.base,
        "POST",
        "/mcp",
        rpc("tools/call", {"name": "echo", "arguments": arguments}),
        headers,
    )
    assert body["error"]["code"] == -32602
    assert body["id"] == 1


def test_unknown_rpc_method_preserves_request_id(connection):
    lab, headers = connection
    _, _, body = request(lab.base, "POST", "/mcp", rpc("unknown", {}, "req"), headers)
    assert body == {
        "jsonrpc": "2.0",
        "id": "req",
        "error": {"code": -32601, "message": "Method not found"},
    }


def test_every_mcp_request_rechecks_auth(connection):
    lab, headers = connection
    assert request(lab.base, "POST", "/mcp", rpc("tools/list", {}), headers)[0] == 200
    assert request(lab.base, "POST", "/mcp", rpc("tools/list", {}))[0] == 401


def test_user_text_and_bearer_never_enter_trace(connection):
    lab, headers = connection
    request(
        lab.base,
        "POST",
        "/mcp",
        rpc("tools/call", {"name": "echo", "arguments": {"text": "PRIVATE-SENTINEL"}}),
        headers,
    )
    trace = str(lab.recorder.events("test"))
    assert "PRIVATE-SENTINEL" not in trace
    assert headers["Authorization"] not in trace


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"jsonrpc": "1.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": True, "method": "tools/list"},
    ],
)
def test_invalid_rpc_shape_is_bounded(connection, payload):
    lab, headers = connection
    status, _, body = request(lab.base, "POST", "/mcp", payload, headers)
    assert status == 400
    assert body["error"]["code"] == -32600
