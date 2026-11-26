from __future__ import annotations

import warnings

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.cache import Cache
from app.config import SegmentConfig, Settings
from app.mdns import extract_parsed_records, pack_records, parse_packet, service_records

warnings.filterwarnings("ignore", category=DeprecationWarning)

SETTINGS = Settings(
    segments=(
        SegmentConfig("station-a", 0, "10.20.1.0/24"),
        SegmentConfig("station-b", 0, "10.20.2.0/24"),
    ),
    join_multicast=False,
)


def push(cache: Cache, segment: str, payload: bytes, now: float = 1000.0) -> None:
    parsed, unsupported = extract_parsed_records(parse_packet(payload))
    cache.ingest(parsed, segment, unsupported=unsupported, now=now)


@pytest.fixture
def clock():
    class C:
        now = 1000.0

        def __call__(self):
            return self.now

    return C()


@pytest.fixture
def client(clock):
    cache = Cache(clock=clock)
    app = create_app(SETTINGS, cache, start_listeners=False)
    with TestClient(app) as c:
        c.app_state = app.state
        c.clock = clock
        c.cache = cache
        yield c


def announce(instance="Front Desk", address="10.20.1.10") -> bytes:
    return pack_records(service_records(instance=instance, address=address))


def test_health(client):
    body = client.get("/api/health").json()
    assert body == {"status": "ok", "segments": ["station-a", "station-b"]}


def test_query_requires_segment_when_ambiguous(client):
    response = client.get("/api/segments//services")
    assert response.status_code in (307, 404, 400)


def test_query_by_segment_id(client):
    push(client.cache, "station-a", announce(), client.clock())
    response = client.get(
        "/api/segments/station-a/services", params={"service": "_ipp._tcp.local."}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["segment"] == "station-a"
    assert body["subnet"] == "10.20.1.0/24"
    assert body["count"] == 1
    service = body["services"][0]
    assert service["instance"] == "Front Desk"
    assert service["ip"] == "10.20.1.10"
    assert service["port"] == 631
    assert service["remaining_ttl"] == 120.0
    assert set(service["records"]) == {"ptr", "srv", "a"}
    assert service["records"]["a"] == {
        "ttl": 120,
        "remaining_ttl": 120.0,
        "in_grace": False,
    }


def test_query_by_subnet_literal(client):
    push(client.cache, "station-b", announce(address="10.20.2.15"), client.clock())
    response = client.get(
        "/api/services",
        params={"segment": "10.20.2.0/24", "service": "_ipp._tcp.local."},
    )
    assert response.status_code == 200
    assert response.json()["segment"] == "station-b"
    assert response.json()["services"][0]["ip"] == "10.20.2.15"


def test_unknown_segment_and_subnet(client):
    assert client.get("/api/segments/nope/services").status_code == 404
    response = client.get("/api/services", params={"segment": "10.99.0.0/24"})
    assert response.status_code == 404
    response = client.get("/api/services", params={"segment": "not-a-net"})
    assert response.status_code == 404


def test_invalid_service_type_is_422(client):
    response = client.get(
        "/api/segments/station-a/services", params={"service": "not a service"}
    )
    assert response.status_code == 422


def test_default_service_type(client):
    push(client.cache, "station-a", announce(), client.clock())
    body = client.get("/api/segments/station-a/services").json()
    assert body["service"] == "_ipp._tcp.local."
    assert body["count"] == 1


def test_segment_isolation_over_http(client):
    push(client.cache, "station-a", announce(address="10.20.1.10"), client.clock())
    a = client.get("/api/segments/station-a/services").json()
    b = client.get("/api/segments/station-b/services").json()
    assert a["count"] == 1 and b["count"] == 0


def test_records_endpoint_and_status(client):
    push(client.cache, "station-a", announce(), client.clock())
    rows = client.get("/api/segments/station-a/records").json()
    assert {row["type"] for row in rows} == {"PTR", "SRV", "A"}
    assert all(row["segment"] == "station-a" for row in rows)
    status = client.get("/api/status").json()
    assert status["cache_entries"] == 3
    assert status["stats"]["records_accepted"] == 3
    assert {s["id"] for s in status["segments"]} == {"station-a", "station-b"}


def test_grace_visible_then_gone_over_http(client):
    push(client.cache, "station-a", announce(), client.clock())
    client.clock.now += 5
    goodbye = pack_records(
        service_records(instance="Front Desk", address="10.20.1.10", ttl_override=0)
    )
    push(client.cache, "station-a", goodbye, client.clock())
    body = client.get("/api/segments/station-a/services").json()
    assert body["count"] == 1
    assert body["services"][0]["remaining_ttl"] == 1.0
    client.clock.now += 1.01
    assert client.get("/api/segments/station-a/services").json()["count"] == 0


def test_openapi_available(client):
    spec = client.get("/openapi.json").json()
    assert "/api/segments/{segment}/services" in spec["paths"]
