import json
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from flight_recorder.oauth import challenge


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(base, method, path, data=None, headers=None, form=False, run="test"):
    supplied = {"X-Recorder-Run": run, **(headers or {})}
    body = None
    if data is not None:
        body = urlencode(data).encode() if form else json.dumps(data).encode()
        supplied["Content-Type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    req = Request(base + path, body, supplied, method=method)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, response.headers, json.loads(raw) if raw else None


def issue(base, run="test", scope="mcp:echo"):
    _, _, registration = request(
        base,
        "POST",
        "/oauth/register",
        {
            "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        },
        run=run,
    )
    verifier = "a" * 43
    params = {
        "client_id": registration["client_id"],
        "redirect_uri": "http://127.0.0.1/callback",
        "response_type": "code",
        "resource": base + "/mcp",
        "scope": scope,
        "state": "state-sentinel",
        "code_challenge_method": "S256",
        "code_challenge": challenge(verifier),
    }
    status, headers, _ = request(
        base, "GET", "/oauth/authorize?" + urlencode(params), run=run
    )
    assert status == 302
    from urllib.parse import parse_qs, urlsplit

    callback = parse_qs(urlsplit(headers["Location"]).query)
    assert callback["state"] == [params["state"]]
    data = {
        "grant_type": "authorization_code",
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "resource": params["resource"],
        "code": callback["code"][0],
        "code_verifier": verifier,
    }
    return data
