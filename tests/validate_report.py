#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def validate(report: object) -> None:
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    if report.get("schema_version") != 1:
        raise ValueError("unsupported schema_version")
    if not isinstance(report.get("generated_at"), str):
        raise ValueError("generated_at must be a string")
    if not isinstance(report.get("system"), dict):
        raise ValueError("system must be an object")
    if not isinstance(report.get("process_count"), int) or report["process_count"] < 0:
        raise ValueError("process_count must be zero or greater")
    if not isinstance(report.get("network_sockets"), list):
        raise ValueError("network_sockets must be an array")
    checks = report.get("audit_checks")
    if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
        raise ValueError("audit_checks must be an array of objects")


def main() -> int:
    try:
        source = Path(sys.argv[1]).read_text(encoding="utf-8") if len(sys.argv) > 1 else sys.stdin.read()
        validate(json.loads(source))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"invalid SuperiorSec report. {error}", file=sys.stderr)
        return 1
    print("report schema is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
