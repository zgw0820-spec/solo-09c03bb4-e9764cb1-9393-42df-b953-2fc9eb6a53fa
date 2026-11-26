#!/usr/bin/env python3
"""Send a DNS-SD PTR/SRV/A announcement or goodbye to one UDP segment port.

Examples
--------
Announce "Front Desk" at 10.20.1.10:631 on segment station-a (udp/5353):

    python scripts/send_packet.py --port 5353 --instance "Front Desk" --ip 10.20.1.10

Goodbye (TTL=0) for the same instance:

    python scripts/send_packet.py --port 5353 --instance "Front Desk" \
        --ip 10.20.1.10 --goodbye

Replace an address with a cache-flush packet (old A gets a 1s grace):

    python scripts/send_packet.py --port 5353 --instance "Front Desk" \
        --ip 10.20.1.99 --flush

Send only the A record, to exercise split-packet refresh:

    python scripts/send_packet.py --port 5353 --ip 10.20.1.99 --only a
"""

from __future__ import annotations

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.mdns import describe_rr, pack_records, service_records  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1", help="destination host")
    parser.add_argument(
        "--port", type=int, required=True, help="destination UDP port (one segment)"
    )
    parser.add_argument("--instance", default="Front Desk", help="DNS-SD instance name")
    parser.add_argument(
        "--service", default="_ipp._tcp.local.", help="DNS-SD service type"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="SRV target host name (default: derived from --instance)",
    )
    parser.add_argument("--ip", required=True, help="IPv4 address for the A record")
    parser.add_argument("--port-ipp", dest="ipp_port", type=int, default=631, help="SRV port")
    parser.add_argument("--ptr-ttl", type=int, default=4500)
    parser.add_argument("--srv-ttl", type=int, default=120)
    parser.add_argument("--a-ttl", type=int, default=120)
    parser.add_argument(
        "--goodbye",
        action="store_true",
        help="send TTL=0 goodbye records instead of an announcement",
    )
    parser.add_argument(
        "--no-flush",
        action="store_true",
        help="clear the cache-flush bit that SRV/A carry by default",
    )
    parser.add_argument(
        "--only",
        choices=["ptr", "srv", "a", "ptr,srv", "srv,a"],
        help="send only a subset of records (simulates packet fragmentation)",
    )
    parser.add_argument("--dry-run", action="store_true", help="print, do not send")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    flush = not args.no_flush
    target = args.target
    if target is None:
        slug = "".join(
            char.lower() if char.isalnum() else "-" for char in args.instance
        ).strip("-")
        target = f"{slug or 'printer'}.local."
    records = service_records(
        instance=args.instance,
        address=args.ip,
        service=args.service,
        target=target,
        port=args.ipp_port,
        ptr_ttl=args.ptr_ttl,
        srv_ttl=args.srv_ttl,
        a_ttl=args.a_ttl,
        flush=flush,
        ttl_override=0 if args.goodbye else None,
    )
    if args.only:
        wanted = set(args.only.split(","))
        records = [
            rr
            for key, rr in zip(("ptr", "srv", "a"), records)
            if key in wanted
        ]

    wire = pack_records(records)
    for rr in records:
        print("record:", describe_rr(rr), file=sys.stderr)
    print(f"packet: {len(wire)} bytes -> {args.host}:{args.port}", file=sys.stderr)
    print(wire.hex())
    if args.dry_run:
        return 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(wire, (args.host, args.port))
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
