import pytest

from flight_recorder.oauth import Authority, OAuthError, challenge

VERIFIER = "a" * 43
REDIRECT = "http://127.0.0.1/callback"
RESOURCE = "http://127.0.0.1:8888/mcp"


def grant(authority, scope="mcp:echo"):
    client = authority.register([REDIRECT])
    params = dict(client_id=client, redirect_uri=REDIRECT, resource=RESOURCE,
                  code_challenge=challenge(VERIFIER), code_challenge_method="S256",
                  response_type="code", scope=scope, state="synthetic-state")
    code = authority.authorize(params)
    token = dict(client_id=client, redirect_uri=REDIRECT, resource=RESOURCE,
                 code=code, code_verifier=VERIFIER, grant_type="authorization_code")
    return params, token


def test_s256_matches_rfc7636_vector():
    assert challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_token_works_once_code_cannot_be_reused():
    authority = Authority(RESOURCE)
    _, data = grant(authority)
    token = authority.exchange(data)
    assert authority.check("Bearer " + token) == "ok"
    with pytest.raises(OAuthError, match="invalid_grant"):
        authority.exchange(data)


@pytest.mark.parametrize("field,value,reason", [
    ("code_verifier", "b" * 43, "pkce_mismatch"),
    ("resource", "http://elsewhere.invalid/mcp", "resource_mismatch"),
    ("client_id", "unknown", "invalid_client"),
    ("redirect_uri", "http://127.0.0.1/other", "invalid_redirect"),
    ("grant_type", "password", "malformed"),
])
def test_exchange_binds_grant(field, value, reason):
    authority = Authority(RESOURCE)
    _, data = grant(authority)
    data[field] = value
    with pytest.raises(OAuthError, match=reason):
        authority.exchange(data)


def test_expiry_and_scope_are_distinct():
    clock = [0.0]
    authority = Authority(RESOURCE, clock=lambda: clock[0])
    _, data = grant(authority)
    token = authority.exchange(data)
    clock[0] = 61.0
    assert authority.check("Bearer " + token) == "expired_token"
    _, data = grant(authority, scope="mcp:connect")
    token = authority.exchange(data)
    assert authority.check("Bearer " + token) == "insufficient_scope"


@pytest.mark.parametrize("redirect", ["https://evil.invalid/callback", "http://localhost.evil/callback", "http://127.0.0.1/callback?x=1"])
def test_registration_rejects_unapproved_redirects(redirect):
    with pytest.raises(OAuthError):
        Authority(RESOURCE).register([redirect])


@pytest.mark.parametrize("field,value", [("code_challenge_method", "plain"), ("state", ""), ("scope", "admin"), ("code_challenge", "short")])
def test_authorization_rejects_invalid_parameters(field, value):
    authority = Authority(RESOURCE)
    params, _ = grant(authority)
    params[field] = value
    with pytest.raises(OAuthError):
        authority.authorize(params)


def test_expired_authorization_code_rejected():
    clock = [0.0]
    authority = Authority(RESOURCE, clock=lambda: clock[0])
    _, data = grant(authority)
    clock[0] = 61.0
    with pytest.raises(OAuthError, match="invalid_grant"):
        authority.exchange(data)
