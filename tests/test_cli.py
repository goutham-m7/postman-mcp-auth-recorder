import json
import signal
import subprocess
import sys

from tests.helpers import issue, request


def test_one_command_demo_produces_complete_bundle(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "flight_recorder", "demo", "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Fault localization: 6/6" in result.stdout
    assert "Raw credentials in exported artifacts: 0" in result.stdout
    assert "POST /oauth/token" in result.stdout
    assert "POST /mcp" in result.stdout
    report = json.loads((tmp_path / "report.json").read_text())
    assert len(report["scenarios"]) == 7


def test_single_case_replay_is_independently_reproducible(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "flight_recorder",
            "demo",
            "--case",
            "missing_bearer",
            "--out",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert "Fault localization: 1/1" in result.stdout


def test_manual_server_captures_safe_facts_and_closes_on_interrupt(tmp_path):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "flight_recorder",
            "serve",
            "--port",
            "0",
            "--out",
            str(tmp_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = process.stdout.readline().strip()
        assert line.startswith("Listening: http://127.0.0.1:"), line
        base = line.removeprefix("Listening: ")
        data = issue(base, run="desktop")
        _, _, token = request(
            base, "POST", "/oauth/token", data, form=True, run="desktop"
        )
        request(base, "POST", "/mcp", {}, run="desktop")
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
        captured = (tmp_path / "desktop.timeline.json").read_text()
        assert token["access_token"] not in captured
        assert data["code_verifier"] not in captured
        assert "missing_authorization" in captured
        assert "Captured" in stdout
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
