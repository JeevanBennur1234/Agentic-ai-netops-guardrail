#!/usr/bin/env python3
"""Telemetry-driven remediation supervisor with safe dry-run defaults.

The supervisor watches Ryu's atomic telemetry snapshot and invokes the decision
pipeline only when that snapshot changes. Live block execution is disabled by
default. Enabling it requires an explicit, environment-specific connectivity
checker loaded as module:function.
"""
import argparse
import hashlib
import importlib
import json
import os
import time

from netops_guardrail.controller.decision_gate import DEFAULT_TELEMETRY_PATH, decide


def load_callable(spec):
    """Load an environment-specific zero-argument connectivity checker."""
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("checker must be specified as module:function")
    module = importlib.import_module(module_name)
    callback = getattr(module, attribute, None)
    if not callable(callback):
        raise ValueError(f"{spec!r} does not identify a callable")
    return callback


def telemetry_fingerprint(path):
    """Hash the complete telemetry snapshot so unchanged data is not reprocessed."""
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry", default=DEFAULT_TELEMETRY_PATH)
    parser.add_argument("--interval", type=float, default=15.0,
                        help="seconds between telemetry checks (default: 15)")
    parser.add_argument("--once", action="store_true",
                        help="run one decision pass and exit")
    parser.add_argument("--execute", action="store_true",
                        help="allow approved actions to reach the executor; blocks also require a live checker")
    parser.add_argument("--connectivity-checker", default=None,
                        help="environment-specific callback in module:function form; required with --execute")
    return parser


def run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.execute and not args.connectivity_checker:
        parser.error("--execute requires --connectivity-checker module:function")

    checker = None
    if args.connectivity_checker:
        try:
            checker = load_callable(args.connectivity_checker)
        except Exception as exc:
            parser.error(f"could not load connectivity checker: {exc}")

    last_fingerprint = None
    exit_code = 0
    print(json.dumps({
        "service": "Agentic AI-NetOps Guardrail",
        "mode": "execute" if args.execute else "dry-run",
        "telemetry": os.path.abspath(args.telemetry),
        "interval_seconds": args.interval,
        "once": args.once,
    }, indent=2), flush=True)

    while True:
        try:
            fingerprint = telemetry_fingerprint(args.telemetry)
            if args.once or fingerprint != last_fingerprint:
                result = decide(
                    telemetry_path=args.telemetry,
                    execute_approved=args.execute,
                    connectivity_checker=checker,
                )
                print(json.dumps({
                    "telemetry_sha256": fingerprint,
                    "result": result,
                }, indent=2, default=str), flush=True)
                execution = result.get("execution")
                if execution and execution.get("success") is False:
                    exit_code = 1
                last_fingerprint = fingerprint
        except KeyboardInterrupt:
            print("Supervisor stopped by operator.", flush=True)
            return exit_code
        except Exception as exc:
            print(json.dumps({
                "error": f"{type(exc).__name__}: {exc}",
                "telemetry": os.path.abspath(args.telemetry),
            }), flush=True)
            exit_code = 1
            if args.once:
                return exit_code

        if args.once:
            return exit_code
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(run())
