"""End-to-end: real UDP sockets -> listeners -> cache -> HTTP API.

These tests bind ephemeral ports on 127.0.0.1 and drive the service through
actual datagrams, which is as close to the Docker Compose setup as we can get
without a container runtime.
"""

from __future__ import annotations

import socket
import time
import warnings

import pytest
import uvicorn
from app.api import create_app
from app.cache import Cache
from app.config import SegmentConfig, Settings
from app.mdns import pack_records, service_records

warnings.filterwarnings("ignore", category=DeprecationWarning)


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture
def live_service():
    port_a, port_b = free_udp_port(), free_udp_port()
    settings = Settings(
        segments=(
            SegmentConfig("station-a", port_a, "10.20.1.0/24"),
            SegmentConfig("station-b", port_b, "10.20.2.0/24"),
        ),
        bind_host="127.0.0.1",
        http_host="127.0.0.1",
        http_port=0,
        join_multicast=False,
    )
    cache = Cache()
    app = create_app(settings, cache, start_listeners=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    http_port = sock.getsockname()[1]
    sock.close()

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=http_port,
            log_level="warning",
            lifespan="on",
        )
    )
    import threading

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)

    class Live:
        pass

    live = Live()
    live.port_a = port_a
    live.port_b = port_b
    live.http_port = http_port
    live.cache = cache
    live.server = server
    yield live
    server.should_exit = True
    thread.join(timeout=10)


def send(port: int, payload: bytes, host: str = "127.0.0.1") -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (host, port))
    finally:
        sock.close()


def query(live, segment: str, service: str = "_ipp._tcp.local.") -> dict:
    import urllib.parse
    import urllib.request
    import json

    qs = urllib.parse.urlencode({"service": service})
    url = f"http://127.0.0.1:{live.http_port}/api/segments/{segment}/services?{qs}"
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)


def wait_for(live, predicate, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.02)
    return last


def test_two_udp_ports_receive_independently(live_service):
    live = live_service
    send(live.port_a, pack_records(service_records(instance="A Desk", address="10.20.1.10")))
    send(live.port_b, pack_records(service_records(instance="B Desk", address="10.20.2.20")))

    a = wait_for(live, lambda: query(live, "station-a"))
    b = wait_for(live, lambda: query(live, "station-b"))
    assert a["count"] == 1 and a["services"][0]["ip"] == "10.20.1.10"
    assert b["count"] == 1 and b["services"][0]["ip"] == "10.20.2.20"
    assert a["services"][0]["instance"] == "A Desk"
    assert b["services"][0]["instance"] == "B Desk"


def test_packet_split_across_datagrams_over_real_udp(live_service):
    live = live_service
    records = service_records(instance="Split", address="10.20.1.30")
    for rr in records:
        send(live.port_a, pack_records([rr]))
        time.sleep(0.01)
    body = wait_for(live, lambda: query(live, "station-a"))
    assert body["count"] == 1
    assert body["services"][0]["ip"] == "10.20.1.30"


def test_goodbye_over_real_udp_keeps_one_second_grace(live_service):
    live = live_service
    send(live.port_a, pack_records(service_records(instance="Bye", address="10.20.1.40")))
    assert wait_for(live, lambda: query(live, "station-a"))["count"] == 1

    send(
        live.port_a,
        pack_records(service_records(instance="Bye", address="10.20.1.40", ttl_override=0)),
    )

    def grace_visible():
        body = query(live, "station-a")
        if body["count"] == 1 and body["services"][0]["records"]["a"]["in_grace"]:
            return body
        return None

    body = wait_for(live, grace_visible)
    assert body is not None
    assert body["services"][0]["remaining_ttl"] <= 1.0

    gone = wait_for(live, lambda: query(live, "station-a")["count"] == 0, timeout=3)
    assert gone is True


def test_same_name_on_two_segments_over_real_udp(live_service):
    live = live_service
    send(live.port_a, pack_records(service_records(instance="Same", address="10.20.1.50")))
    send(live.port_b, pack_records(service_records(instance="Same", address="10.20.2.50")))
    a = wait_for(live, lambda: query(live, "station-a"))
    b = wait_for(live, lambda: query(live, "station-b"))
    assert a["services"][0]["ip"] == "10.20.1.50"
    assert b["services"][0]["ip"] == "10.20.2.50"

    # Goodbye on segment A only.
    send(
        live.port_a,
        pack_records(service_records(instance="Same", address="10.20.1.50", ttl_override=0)),
    )
    assert wait_for(live, lambda: query(live, "station-a")["count"] == 0, timeout=3)
    body_b = query(live, "station-b")
    assert body_b["count"] == 1 and body_b["services"][0]["ip"] == "10.20.2.50"


def test_malformed_and_query_packets_do_not_corrupt_state(live_service):
    live = live_service
    send(live.port_a, b"\x00\x01\x02")
    from app.mdns import DNSRecord

    send(live.port_a, DNSRecord.question("_ipp._tcp.local.", "PTR").pack())
    send(live.port_a, pack_records(service_records(instance="Good", address="10.20.1.60")))
    body = wait_for(live, lambda: query(live, "station-a"))
    assert body["count"] == 1
    status_url = f"http://127.0.0.1:{live.http_port}/api/status"
    import json
    import urllib.request

    with urllib.request.urlopen(status_url, timeout=5) as response:
        status = json.load(response)
    assert status["stats"]["packets_malformed"] >= 1
    assert status["stats"]["packets_ignored"] >= 1
    assert status["cache_entries"] == 3
