#!/usr/bin/env python3
"""Query the discovery API for one segment's IPP services.

Examples
--------
    python scripts/query.py --segment station-a
    python scripts/query.py --segment 10.20.2.0/24
    python scripts/query.py --segment station-b --service _ipp._tcp.local. --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--segment", required=True, help="segment id or CIDR subnet")
    parser.add_argument("--service", default="_ipp._tcp.local.")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument(
        "--records", action="store_true", help="show raw cache records instead"
    )
    args = parser.parse_args(argv)

    if args.records:
        # The records endpoint is keyed by segment id; resolve CIDR input
        # through /api/status first.
        with urllib.request.urlopen(f"{args.base_url}/api/status", timeout=5) as resp:
            status = json.load(resp)
        segment_id = args.segment
        for entry in status["segments"]:
            if entry["id"] == args.segment or entry["subnet"] == args.segment:
                segment_id = entry["id"]
        with urllib.request.urlopen(
            f"{args.base_url}/api/segments/{segment_id}/records", timeout=5
        ) as resp:
            print(json.dumps(json.load(resp), indent=2, ensure_ascii=False))
        return 0

    params = urllib.parse.urlencode(
        {"segment": args.segment, "service": args.service}
    )
    with urllib.request.urlopen(f"{args.base_url}/api/services?{params}", timeout=5) as resp:
        body = json.load(resp)

    if args.json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0

    print(f"segment {body['segment']} ({body['subnet']}) {body['service']}")
    if not body["services"]:
        print("  no services")
        return 0
    for service in body["services"]:
        print(
            f"  {service['instance']}  {service['ip']}:{service['port']}  "
            f"remaining={service['remaining_ttl']}s"
        )
        for name in ("ptr", "srv", "a"):
            record = service["records"][name]
            grace = " grace" if record["in_grace"] else ""
            print(
                f"    {name.upper():3} ttl={record['ttl']:5d} "
                f"remaining={record['remaining_ttl']:7.2f}s{grace}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
