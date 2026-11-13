"""Small stateless MCP JSON response transport, protocol 2025-06-18."""

PROTOCOL = "2025-06-18"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "auth-flight-recorder", "version": "0.1.0"},
    },
}
ECHO = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {"text": "synthetic hello"}},
}


def handle(request):
    request_id = request.get("id")

    def error(code, message, status=200):
        return (
            status,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            },
            "rpc_error",
        )

    if (
        request.get("jsonrpc") != "2.0"
        or not isinstance(request.get("method"), str)
        or ("id" in request and type(request_id) not in (str, int))
    ):
        request_id = None
        return error(-32600, "Invalid Request", 400)
    method = request["method"]
    if "id" not in request:
        return 202, None, "notification"
    params = request.get("params", {})
    if not isinstance(params, dict):
        return error(-32602, "Invalid params")
    if method == "initialize":
        if (
            not isinstance(params.get("protocolVersion"), str)
            or not isinstance(params.get("capabilities"), dict)
            or not isinstance(params.get("clientInfo"), dict)
        ):
            return error(-32602, "Invalid params")
        result = {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "synthetic-auth-lab", "version": "0.1.0"},
        }
        reason = "initialized"
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo synthetic text; never stored in traces",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string", "maxLength": 1024}},
                        "required": ["text"],
                        "additionalProperties": False,
                    },
                }
            ]
        }
        reason = "tools_listed"
    elif method == "tools/call":
        arguments = params.get("arguments")
        if (
            params.get("name") != "echo"
            or not isinstance(arguments, dict)
            or set(arguments) != {"text"}
            or not isinstance(arguments["text"], str)
            or len(arguments["text"]) > 1024
        ):
            return error(-32602, "Invalid params")
        result = {
            "content": [{"type": "text", "text": arguments["text"]}],
            "isError": False,
        }
        reason = "echo"
    else:
        return error(-32601, "Method not found")
    return 200, {"jsonrpc": "2.0", "id": request_id, "result": result}, reason
