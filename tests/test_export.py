import json
import subprocess
from pathlib import Path

import pytest

from flight_recorder.export import collection, export_bundle
from flight_recorder.replay import run_case
from flight_recorder.server import LabServer


def test_exports_never_contain_observed_credentials(tmp_path):
    valid, secrets = run_case("valid")
    broken, more = run_case("missing_bearer")
    paths = export_bundle(tmp_path, [valid, broken], secrets | more)
    assert {p.name for p in paths} == {
        "report.json",
        "timeline.html",
        "postman.collection.json",
        "repro.json",
        "checksums.json",
    }
    exported = "".join(path.read_text() for path in paths)
    assert all(secret not in exported for secret in secrets | more)
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["metrics"]["raw_credentials_in_exports"] == 0
    assert report["metrics"]["localized_faults"] == 1
    assert "missing_authorization" in (tmp_path / "timeline.html").read_text()


def test_secret_scan_aborts_before_writing(tmp_path):
    result, _ = run_case("valid")
    result["case"] = "LEAK-SENTINEL"
    with pytest.raises(ValueError, match="Credential"):
        export_bundle(tmp_path, [result], {"LEAK-SENTINEL"})
    assert list(tmp_path.iterdir()) == []


def test_html_escapes_dynamic_labels(tmp_path):
    result, secrets = run_case("valid")
    result["case"] = "<script>alert(1)</script>"
    export_bundle(tmp_path, [result], secrets)
    html = (tmp_path / "timeline.html").read_text()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_collection_replays_through_public_newman_runner(tmp_path):
    runner = Path("node_modules/newman/bin/newman.js")
    assert runner.exists(), "Run npm ci before the full suite"
    with LabServer() as lab:
        path = tmp_path / "collection.json"
        path.write_text(json.dumps(collection(lab.base)))
        result = subprocess.run(
            [
                "node",
                str(runner),
                "run",
                str(path),
                "--reporters",
                "cli",
                "--reporter-cli-no-console",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        events = lab.recorder.events("collection")
        assert [event["reason"] for event in events] == [
            "challenge",
            "discovery",
            "discovery",
            "registered",
            "authorized",
            "token_issued",
            "initialized",
            "notification",
            "tools_listed",
            "echo",
            "missing_authorization",
        ]
        assert events[6]["authorization_present"] is True
        assert events[-1]["authorization_present"] is False
