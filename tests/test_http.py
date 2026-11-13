from urllib.parse import urlencode

import pytest

from flight_recorder.server import LabServer
from tests.helpers import issue, request


@pytest.fixture
def lab():
    with LabServer() as server:
        yield server


def test_discovery_documents_use_bound_address_not_host(lab):
    status, _, data = request(
        lab.base, "GET", "/.well-known/oauth-protected-resource/mcp"
    )
    assert status == 200
    assert data["resource"] == lab.base + "/mcp"
    assert data["authorization_servers"] == [lab.base]
    _, _, metadata = request(lab.base, "GET", "/.well-known/oauth-authorization-server")
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert metadata["token_endpoint"] == lab.base + "/oauth/token"


def test_anonymous_mcp_challenges_with_resource_metadata(lab):
    status, headers, _ = request(lab.base, "POST", "/mcp", {})
    assert status == 401
    assert 'resource_metadata="' + lab.base in headers["WWW-Authenticate"]
    assert lab.recorder.events("test")[-1]["reason"] == "challenge"


def test_real_pkce_exchange_and_cache_headers(lab):
    data = issue(lab.base)
    status, headers, token = request(lab.base, "POST", "/oauth/token", data, form=True)
    assert status == 200
    assert token["token_type"] == "Bearer"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Pragma"] == "no-cache"
    status, _, _ = request(lab.base, "POST", "/oauth/token", data, form=True)
    assert status == 400


def test_missing_header_after_token_is_not_discovery(lab):
    request(lab.base, "POST", "/oauth/token", issue(lab.base), form=True)
    assert request(lab.base, "POST", "/mcp", {})[0] == 401
    assert lab.recorder.events("test")[-1]["reason"] == "missing_authorization"


@pytest.mark.parametrize(
    "headers", [{"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"}]
)
def test_browser_origin_and_dns_rebinding_are_denied(lab, headers):
    assert (
        request(
            lab.base, "GET", "/.well-known/oauth-authorization-server", headers=headers
        )[0]
        == 403
    )


def test_duplicate_form_parameters_are_rejected(lab):
    status, _, _ = request(
        lab.base,
        "GET",
        "/oauth/authorize?" + urlencode([("state", "one"), ("state", "two")]),
    )
    assert status == 400


def test_bad_registration_and_json_shapes_fail_closed(lab):
    for data in (
        ["not", "object"],
        {"redirect_uris": ["https://evil.invalid/callback"]},
        {
            "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    ):
        assert request(lab.base, "POST", "/oauth/register", data)[0] == 400


def test_query_credentials_are_rejected_and_not_recorded(lab):
    assert request(lab.base, "POST", "/mcp?access_token=SENTINEL", {})[0] == 400
    assert "SENTINEL" not in str(lab.recorder.events("test"))
