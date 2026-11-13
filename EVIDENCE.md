# Observed verification

## Fresh local clone

A new local `git clone --no-hardlinks` into a temporary directory was used, not the working tree or its dependency directories. On macOS arm64, Python 3.15.0 and Node 22.23.4:

```text
make setup
  pytest 8.4.2, Ruff 0.14.5, Newman 6.2.3 installed
make check
  Ruff: All checks passed!
  Ruff format: 18 files already formatted
  pytest: 62 passed in 1.92s
make demo
  Fault localization: 6/6
  Raw credentials in exported artifacts: 0
  Max failed-response-to-diagnosis: 0.020 ms
```

Setup uses package registries; tests and demo then use only local sockets with no API key or external service. npm emitted upstream deprecation warnings for har-validator, uuid and the legacy faker package; no install failure. No hosted CI execution or desktop UI test is claimed. CI is configured for Python 3.11/3.13; those versions were not run locally.

## Acceptance evidence

| ID | Delivered proof | Artifact / exercised assertion | Result |
|---|---|---|---|
| EC-1 | Real HTTP integration | `tests/test_mcp.py::test_initialize_notification_list_and_echo_over_http`: discovery/PKCE token, initialize, notification, tool list and exact echo payload | Pass |
| EC-2 | Real HTTP integration + captured demo | `tests/test_replay.py::test_reported_symptom_and_valid_timeline_share_oauth_prefix`; [sample report](examples/report.json): first six safe events match, then bearer presence diverges at initialize | Pass |
| EC-3 | Real HTTP integration + captured report | `tests/test_replay.py::test_seeded_fault_localization`, six negative cases plus valid control; 6/6 exact boundary/reason matches | Pass |
| EC-4 | Integration export and failure tests | `tests/test_export.py::test_exports_never_contain_observed_credentials`, `test_secret_scan_aborts_before_writing`; all generated token/code/verifier/state/client-ID values scanned across JSON, HTML and collection before writes | Pass |
| EC-5 | Unit + real HTTP integration | `tests/test_oauth.py` grant/PKCE/client/redirect/resource/expiry cases; `tests/test_http.py::test_real_pkce_exchange_and_cache_headers`; concurrent redemption in `tests/test_boundaries.py` returns exactly one 200 and three 400s | Pass |
| EC-6 | Public Postman runner integration | `tests/test_export.py::test_collection_replays_through_public_newman_runner`: actual Newman executes all 12 exported requests and scripts; server-side event sequence confirms protected echo and deliberate missing-header 401 | Pass |

The CLI is also tested as a subprocess, including isolated single-case replay and a manual `serve` target interrupted with SIGINT. It writes a safe capture and exits successfully; the tests close their servers in context managers. No persistent demo server is required or left running.

## Captured visual report

Opened the generated static HTML in the local browser and inspected its rendered screenshot. At a 488 CSS-pixel viewport: seven scenario sections, six highlighted failed-boundary rows, zero script elements, and no whole-page horizontal overflow. Tables retain local overflow handling. Closed the browser tab afterward. This is a report-rendering check, not native Postman verification.

## Reproduction and metric interpretation

[The sample bundle](examples/repro.json) identifies itself as `synthetic-wire-symptom`, with `desktop_verified: false`. The original issue is a user report; its comments do not support a reliable desktop-version bisect. The valid and missing-bearer prefixes are generated against the same fixture, without proprietary Postman code.

`failure_to_diagnosis_ms` measures time from the local replay client receiving the failing response until in-memory classification completes. It excludes consent/OAuth duration and human debugging. The headline measures seeded-case correctness, not general remote-server root-cause accuracy.

The sample stdout and bundle in `examples/` came from an earlier actual run (0.022 ms maximum); fresh-clone timing was 0.020 ms. Timings are intentionally not normalized or presented as a speedup.

## Portability and credential check

Before the final documentation commit, repository text was searched for absolute macOS home paths and common AWS, GitHub, private-key, OpenAI-style and Slack credential patterns: no matches. Ignored dependency/cache directories were excluded. The exporter separately scans exact credentials observed during its synthetic run. This is bounded evidence, not a comprehensive secret-audit certification.

No remote is configured in the source repository; no push, package publication, company contact, or account creation occurred. All implementation and fixtures are new and synthetic; public Newman is used as a dependency, not vendored.
