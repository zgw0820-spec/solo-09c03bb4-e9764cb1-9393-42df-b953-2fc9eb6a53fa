from __future__ import annotations

import os
import sys
import warnings

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.filterwarnings(
    "ignore",
    message="Using `httpx` with `starlette.testclient` is deprecated",
)

from app.mdns import (  # noqa: E402
    extract_parsed_records,
    pack_records,
    parse_packet,
    service_records,
)


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def packet_builder():
    """Build wire packets from PTR/SRV/A RRs."""

    def build(records, qr: bool = True) -> bytes:
        return pack_records(records, qr=qr)

    return build


@pytest.fixture
def announce():
    """Convenience: build a full PTR/SRV/A announcement packet."""

    def build(**kwargs) -> bytes:
        return pack_records(service_records(**kwargs))

    return build


def parsed_of(payload: bytes):
    record = parse_packet(payload)
    parsed, unsupported = extract_parsed_records(record)
    return parsed, unsupported
