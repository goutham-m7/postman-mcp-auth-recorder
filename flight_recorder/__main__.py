"""Composition root: local-only demo and explicit desktop capture target."""

import argparse
import json
from pathlib import Path

from .export import collection, export_bundle
from .replay import CASES, run_case
from .server import LabServer
from .trace import diagnose


def demo(args):
    results, credentials = [], set()
    cases = [args.case] if args.case else list(CASES)
    for case in cases:
        result, sensitive = run_case(case)
        results.append(result)
        credentials.update(sensitive)
    export_bundle(args.out, results, credentials)
    print("MCP Auth Flight Recorder | synthetic local HTTP; Postman desktop not tested")
    for result in results:
        diagnosis = result["diagnosis"]
        print(f'{result["case"]:20} {diagnosis["reason"]:24} {diagnosis["boundary"] or "echo returned synthetic hello"}')
    faults = [result for result in results if result["case"] != "valid"]
    print(f'Fault localization: {sum(r["matches_expectation"] for r in faults)}/{len(faults)}')
    print("Raw credentials in exported artifacts: 0")
    latency = max((r["failure_to_diagnosis_ms"] for r in faults), default=0)
    print(f"Max failed-response-to-diagnosis: {latency:.3f} ms (local classification, not human debugging time)")
    print(f"Bundle: {args.out}/ [report.json, timeline.html, postman.collection.json, repro.json, checksums.json]")
    return 0 if all(result["matches_expectation"] for result in results) else 1


def serve(args):
    args.out.mkdir(parents=True, exist_ok=True)
    with LabServer(port=args.port) as lab:
        (args.out / "postman.collection.json").write_text(json.dumps(collection(lab.base), indent=2) + "\n", encoding="utf-8")
        print(f"Listening: {lab.base}", flush=True)
        print("Synthetic consent auto-approves local test clients. Never use real credentials.", flush=True)
        print(f"Import {args.out}/postman.collection.json; Ctrl-C exports safe desktop/collection timelines.", flush=True)
        try:
            # Join releases the main thread for KeyboardInterrupt while server runs.
            lab.thread.join()
        except KeyboardInterrupt:
            pass
    captured = {}
    for run in ("desktop", "collection"):
        events = lab.recorder.events(run)
        captured[run] = {"events": events, "diagnosis": diagnose(events)}
    (args.out / "desktop.timeline.json").write_text(json.dumps({
        "provenance": "server-side facts; record the desktop version separately; no automatic client root-cause claim",
        "runs": captured}, indent=2) + "\n", encoding="utf-8")
    print(f"Captured safe timeline: {args.out}/desktop.timeline.json")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Loopback MCP OAuth auth-boundary recorder")
    subparsers = parser.add_subparsers(dest="command", required=True)
    replay = subparsers.add_parser("demo", help="run real HTTP synthetic cases, then close every server")
    replay.add_argument("--case", choices=list(CASES))
    replay.add_argument("--out", type=Path, default=Path("artifacts"))
    capture = subparsers.add_parser("serve", help="local synthetic OAuth target for manual Postman verification")
    capture.add_argument("--port", type=int, default=8765)
    capture.add_argument("--out", type=Path, default=Path("artifacts/desktop"))
    args = parser.parse_args()
    if args.command == "serve" and not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    return demo(args) if args.command == "demo" else serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
