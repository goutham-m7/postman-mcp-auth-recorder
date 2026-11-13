"""Shareable artifacts are constructed from safe facts and scanned before writing."""

import hashlib
import html
import json
from pathlib import Path
from urllib.parse import urlencode

from .mcp import ECHO, INITIALIZE

SOURCE = "https://github.com/postmanlabs/postman-app-support/issues/14119"


def collection(base="http://127.0.0.1:8765"):
    """Collection v2.1. Runtime-only local variables never store tokens in the file."""
    items = []

    def add(name, method, path, status, data=None, bearer=False, script="", form=False):
        headers = [
            {"key": "X-Recorder-Run", "value": "{{run_id}}"},
            {"key": "Accept", "value": "application/json, text/event-stream"},
        ]
        if bearer:
            headers.append({"key": "Authorization", "value": "Bearer {{access_token}}"})
        request = {
            "method": method,
            "url": "{{base_url}}" + path,
            "header": headers,
            "auth": {"type": "noauth"},
        }
        if data is not None:
            if form:
                request["body"] = {
                    "mode": "urlencoded",
                    "urlencoded": [{"key": k, "value": v} for k, v in data.items()],
                }
            else:
                request["body"] = {
                    "mode": "raw",
                    "raw": json.dumps(data),
                    "options": {"raw": {"language": "json"}},
                }
            headers.append(
                {
                    "key": "Content-Type",
                    "value": "application/x-www-form-urlencoded"
                    if form
                    else "application/json",
                }
            )
        items.append(
            {
                "name": name,
                "request": request,
                "protocolProfileBehavior": {"followRedirects": False},
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "type": "text/javascript",
                            "exec": [
                                f'pm.test("HTTP {status}", () => pm.response.to.have.status({status}));',
                                *script.splitlines(),
                            ],
                        },
                    }
                ],
            }
        )

    add(
        "01 Anonymous MCP challenge",
        "POST",
        "/mcp",
        401,
        INITIALIZE,
        script='pm.test("Resource metadata challenge", () => pm.expect(pm.response.headers.get("WWW-Authenticate")).to.include("resource_metadata="));',
    )
    items[0]["event"].insert(
        0,
        {
            "listen": "prerequest",
            "script": {
                "type": "text/javascript",
                "exec": [
                    'const verifier = pm.variables.replaceIn("{{$randomUUID}}{{$randomUUID}}").replace(/-/g, "");',
                    'pm.variables.set("verifier", verifier);',
                    'pm.variables.set("state", pm.variables.replaceIn("{{$randomUUID}}"));',
                    'const crypto = require("crypto-js");',
                    r'pm.variables.set("challenge", crypto.SHA256(verifier).toString(crypto.enc.Base64).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"));',
                ],
            },
        },
    )
    add(
        "02 Resource discovery",
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        200,
        script='pm.test("Resource binding", () => pm.expect(pm.response.json().resource).to.eql(pm.variables.get("base_url") + "/mcp"));',
    )
    add(
        "03 Authorization discovery",
        "GET",
        "/.well-known/oauth-authorization-server",
        200,
        script='pm.test("PKCE S256 advertised", () => pm.expect(pm.response.json().code_challenge_methods_supported).to.include("S256"));',
    )
    add(
        "04 Register synthetic public client",
        "POST",
        "/oauth/register",
        201,
        {
            "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        },
        script='pm.variables.set("client_id", pm.response.json().client_id);',
    )
    params = {
        "client_id": "{{client_id}}",
        "redirect_uri": "http://127.0.0.1/callback",
        "response_type": "code",
        "resource": "{{base_url}}/mcp",
        "scope": "mcp:echo",
        "state": "{{state}}",
        "code_challenge_method": "S256",
        "code_challenge": "{{challenge}}",
    }
    add(
        "05 Synthetic consent (redirect not followed)",
        "GET",
        "/oauth/authorize?" + urlencode(params, safe="{}:/"),
        302,
        script='const location = pm.response.headers.get("Location");\nconst code = decodeURIComponent(location.match(/[?&]code=([^&]+)/)[1]);\nconst state = decodeURIComponent(location.match(/[?&]state=([^&]+)/)[1]);\npm.test("State matches", () => pm.expect(state).to.eql(pm.variables.get("state")));\npm.variables.set("code", code);',
    )
    add(
        "06 Exchange code with verifier",
        "POST",
        "/oauth/token",
        200,
        {
            "grant_type": "authorization_code",
            "client_id": "{{client_id}}",
            "redirect_uri": "http://127.0.0.1/callback",
            "resource": "{{base_url}}/mcp",
            "code": "{{code}}",
            "code_verifier": "{{verifier}}",
        },
        form=True,
        script='pm.variables.set("access_token", pm.response.json().access_token);\npm.test("Token response not cached", () => pm.expect(pm.response.headers.get("Cache-Control")).to.eql("no-store"));',
    )
    add(
        "07 Valid bearer initialize",
        "POST",
        "/mcp",
        200,
        INITIALIZE,
        bearer=True,
        script='pm.test("Initialize result", () => pm.expect(pm.response.json().result.protocolVersion).to.eql("2025-06-18"));',
    )
    add(
        "08 Initialized notification",
        "POST",
        "/mcp",
        202,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        bearer=True,
    )
    add(
        "09 List echo tool",
        "POST",
        "/mcp",
        200,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        bearer=True,
        script='pm.test("Echo available", () => pm.expect(pm.response.json().result.tools[0].name).to.eql("echo"));',
    )
    add(
        "10 Protected echo",
        "POST",
        "/mcp",
        200,
        ECHO,
        bearer=True,
        script='pm.test("Echo exact payload", () => pm.expect(pm.response.json().result.content[0].text).to.eql("synthetic hello"));',
    )
    add(
        "11 Issue 14119 wire symptom: deliberately omit bearer",
        "POST",
        "/mcp",
        401,
        INITIALIZE,
        script='pm.test("MCP denied after token issued", () => pm.expect(pm.response.json().error).to.eql("invalid_token"));\n["access_token", "code", "verifier", "state", "client_id", "challenge"].forEach(k => pm.variables.unset(k));',
    )
    add(
        "12 Fetch token-safe timeline",
        "GET",
        "/recorder/timeline",
        200,
        script='pm.test("Localized missing header", () => pm.expect(pm.response.json().events.slice(-1)[0].reason).to.eql("missing_authorization"));',
    )
    return {
        "info": {
            "name": "MCP Auth Flight Recorder — synthetic #14119 wire reproduction",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/",
            "description": "Local synthetic consent only. Not a native Postman MCP-client test. Runtime credentials use local variables; do not export runner wire reports.",
        },
        "variable": [
            {"key": "base_url", "value": base},
            {"key": "run_id", "value": "collection"},
        ],
        "item": items,
    }


def render(results):
    cards = []
    for result in results:
        rows = []
        for event in result["events"]:
            failed = event["status"] >= 400 and event["reason"] != "challenge"
            css = ' class="fault"' if failed else ""
            cells = [
                event["sequence"],
                f"{event['method']} {event['path']}",
                event["status"],
                "present" if event["authorization_present"] else "absent",
                event["reason"],
            ]
            rows.append(
                f"<tr{css}>"
                + "".join("<td>" + html.escape(str(value)) + "</td>" for value in cells)
                + "</tr>"
            )
        cards.append(
            "<section><h2>"
            + html.escape(result["case"])
            + '</h2><p class="outcome">'
            + html.escape(result["diagnosis"]["reason"])
            + '</p><div class="scroll"><table><caption>Protocol boundary facts; no request bodies or credentials</caption><thead><tr><th scope="col">#</th><th scope="col">Request</th><th scope="col">HTTP</th><th scope="col">Authorization</th><th scope="col">Observation</th></tr></thead><tbody>'
            + "".join(rows)
            + "</tbody></table></div></section>"
        )
    return (
        """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MCP Auth Flight Recorder</title>
<style>
:root{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#17233c;background:#f3f1e9}body{margin:0;padding:3rem;max-width:1500px}header{border-top:5px solid #2450a5;padding-top:1rem}h1{font:600 clamp(2rem,4vw,4rem)/1.05 system-ui;max-width:900px;letter-spacing:-.04em}h2{font:600 1.3rem system-ui}p{line-height:1.6;max-width:850px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,650px),1fr));gap:1.5rem}section{background:#fff;padding:1.5rem;border:1px solid #cbd0d7;border-radius:4px}.outcome{color:#244c91}table{border-collapse:collapse;font-size:.75rem;width:100%}caption{text-align:left;margin-bottom:.8rem;color:#526079}td,th{text-align:left;padding:.7rem .4rem;border-bottom:1px solid #dce0e6;vertical-align:top}.fault{background:#ffe4df;color:#8a1b0e;font-weight:600}.scroll{overflow-x:auto}footer{margin-top:2rem;font-size:.8rem}a{color:#174da5}@media(max-width:700px){body{padding:1rem}section{padding:1rem}}
</style><header><p>LOCAL PROTOCOL LAB / ISSUE #14119</p><h1>Login succeeded.<br>Did the bearer make the next hop?</h1><p>Compare the valid and missing-header flows: the OAuth prefix matches. The first post-token MCP request exposes the boundary. Expected discovery challenges are not failures.</p></header><main class="grid">"""
        + "".join(cards)
        + '</main><footer>All data synthetic. Postman desktop not exercised. <a href="'
        + SOURCE
        + '">Original user report</a>. Tokens, codes, state, PKCE verifier and echo text are never retained in this timeline.</footer></html>'
    )


def export_bundle(directory, results, credentials):
    faults = [result for result in results if result["case"] != "valid"]
    report = {
        "schema_version": 1,
        "source": SOURCE,
        "provenance": "synthetic local client; not Postman desktop",
        "metrics": {
            "localized_faults": sum(r["matches_expectation"] for r in faults),
            "seeded_faults": len(faults),
            "raw_credentials_in_exports": 0,
            "max_failure_to_diagnosis_ms": max(
                (r["failure_to_diagnosis_ms"] for r in faults), default=0
            ),
        },
        "scenarios": results,
    }
    repro = {
        "issue": SOURCE,
        "kind": "synthetic-wire-symptom",
        "desktop_verified": False,
        "command": "python3 -m flight_recorder demo --case missing_bearer",
        "server_command": "python3 -m flight_recorder serve --port 8765",
        "collection": "postman.collection.json",
        "expected": {
            "token_exchange": 200,
            "post_token_initialize": 401,
            "authorization_present": False,
            "reason": "missing_authorization",
        },
    }

    def encode(value):
        return json.dumps(value, indent=2, sort_keys=True) + "\n"

    files = {
        "report.json": encode(report),
        "timeline.html": render(results),
        "postman.collection.json": encode(collection()),
        "repro.json": encode(repro),
    }
    # Fail before creating files, even if a future event schema accidentally widens.
    if any(
        secret and secret in content
        for secret in credentials
        for content in files.values()
    ):
        raise ValueError("Credential detected in export; no artifacts written")
    files["checksums.json"] = encode(
        {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in files.items()
        }
    )
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, content in files.items():
        path = directory / name
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths
