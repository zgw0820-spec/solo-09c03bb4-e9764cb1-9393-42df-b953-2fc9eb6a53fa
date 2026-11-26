"""Configuration for the per-segment mDNS cache service.

A *segment* is the simulated network seen by one UDP listener port.  Real
deployments usually map one UDP port to one VLAN/interface; the sample
deployment uses two ports so both segments can be exercised on one host.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Mapping

DEFAULT_SEGMENTS = "station-a:5353:10.20.1.0/24,station-b:5354:10.20.2.0/24"
DEFAULT_MULTICAST_GROUP = "224.0.0.251"
DEFAULT_MULTICAST_INTERFACE = "0.0.0.0"


def _env_bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SegmentConfig:
    """One simulated network segment."""

    id: str
    port: int
    subnet: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.subnet, strict=True)


@dataclass(frozen=True)
class Settings:
    segments: tuple[SegmentConfig, ...]
    bind_host: str = "0.0.0.0"
    http_host: str = "0.0.0.0"
    http_port: int = 8000
    multicast_group: str = DEFAULT_MULTICAST_GROUP
    multicast_interface: str = DEFAULT_MULTICAST_INTERFACE
    join_multicast: bool = False
    cache_max_records: int = 10_000
    log_level: str = "INFO"

    def segment(self, segment_id: str) -> SegmentConfig | None:
        for segment in self.segments:
            if segment.id == segment_id:
                return segment
        return None

    def segment_by_subnet(self, network: ipaddress.IPv4Network) -> SegmentConfig | None:
        for segment in self.segments:
            if segment.network == network:
                return segment
        return None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        return cls(
            segments=parse_segments(env.get("SEGMENTS", DEFAULT_SEGMENTS)),
            bind_host=env.get("BIND_HOST", "0.0.0.0"),
            http_host=env.get("HTTP_HOST", "0.0.0.0"),
            http_port=int(env.get("HTTP_PORT", "8000")),
            multicast_group=env.get("MULTICAST_GROUP", DEFAULT_MULTICAST_GROUP),
            multicast_interface=env.get(
                "MULTICAST_INTERFACE", DEFAULT_MULTICAST_INTERFACE
            ),
            join_multicast=_env_bool(env.get("JOIN_MULTICAST"), False),
            cache_max_records=int(env.get("CACHE_MAX_RECORDS", "10000")),
            log_level=env.get("LOG_LEVEL", "INFO"),
        )


def parse_segments(raw: str) -> tuple[SegmentConfig, ...]:
    """Parse ``id:port:cidr,id:port:cidr`` into validated segment configs.

    IPv4 only, because the whole cache is keyed by IPv4 A records.
    """

    segments: list[SegmentConfig] = []
    seen_ids: set[str] = set()
    seen_ports: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) != 3:
            raise ValueError(
                f"invalid segment {chunk!r}; expected 'id:port:cidr'"
            )
        segment_id, port_text, cidr = (part.strip() for part in parts)
        if not segment_id:
            raise ValueError(f"segment {chunk!r} has an empty id")
        port = int(port_text)
        if not 0 <= port <= 65535:
            raise ValueError(f"segment {segment_id!r} has invalid port {port}")
        network = ipaddress.ip_network(cidr, strict=True)
        if network.version != 4:
            raise ValueError(
                f"segment {segment_id!r} uses IPv6 subnet {cidr}; IPv4 is required"
            )
        if segment_id in seen_ids:
            raise ValueError(f"duplicate segment id {segment_id!r}")
        if port != 0 and port in seen_ports:
            raise ValueError(f"duplicate UDP port {port}")
        seen_ids.add(segment_id)
        seen_ports.add(port)
        segments.append(SegmentConfig(segment_id, port, str(network)))
    if not segments:
        raise ValueError("at least one segment must be configured")
    return tuple(segments)
