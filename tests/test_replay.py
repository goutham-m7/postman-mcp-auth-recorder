import json

import pytest

from flight_recorder.replay import CASES, run_case


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "missing_bearer",
        "invalid_bearer",
        "expired_token",
        "insufficient_scope",
        "pkce_mismatch",
        "resource_mismatch",
    ],
)
def test_seeded_fault_localization(case):
    result, secrets = run_case(case)
    assert result["diagnosis"]["reason"] == CASES[case][0]
    assert result["diagnosis"]["boundary"] == CASES[case][1]
    assert result["matches_expectation"]
    encoded = json.dumps(result)
    assert all(secret not in encoded for secret in secrets)
    if case != "valid":
        assert result["failure_to_diagnosis_ms"] >= 0


def test_reported_symptom_and_valid_timeline_share_oauth_prefix():
    valid, _ = run_case("valid")
    broken, _ = run_case("missing_bearer")

    def clean(events):
        return [{k: v for k, v in e.items() if k != "elapsed_ms"} for e in events]

    assert clean(valid["events"][:6]) == clean(broken["events"][:6])
    assert valid["events"][6]["authorization_present"] is True
    assert broken["events"][6]["authorization_present"] is False
    assert broken["diagnosis"]["token_issued"] is True


def test_unknown_fault_is_rejected():
    with pytest.raises(ValueError, match="Unknown case"):
        run_case("invented")
