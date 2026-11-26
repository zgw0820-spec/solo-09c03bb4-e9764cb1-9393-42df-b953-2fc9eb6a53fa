"""UDP listeners: one asyncio datagram endpoint per simulated segment.

Each endpoint is bound to ``bind_host:segment.port``.  The receiving port is
what assigns a packet to a segment, so the same names announced on two ports
stay in separate cache worlds.  Multicast group membership is optional: on a
single host two ports cannot be isolated from one group, so the sample
deployment uses unicast/two-port delivery and leaves multicast off.  On a real
LAN, enable it per interface instead.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field

from .config import SegmentConfig, Settings
from .mdns import PacketError, extract_parsed_records, parse_packet

log = logging.getLogger(__name__)


@dataclass
class SegmentListener:
    config: SegmentConfig
    transport: asyncio.DatagramTransport | None = None
    bound_port: int | None = None

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None


@dataclass
class _Protocol(asyncio.DatagramProtocol):
    cache: object
    segment: SegmentConfig
    listener: SegmentListener
    counter: dict[str, int] = field(default_factory=lambda: {"packets": 0})
    _loop: asyncio.AbstractEventLoop | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.listener.transport = transport  # type: ignore[assignment]
        sock = transport.get_extra_info("socket")
        if sock is not None:
            self.listener.bound_port = sock.getsockname()[1]
        log.info(
            "segment %s listening on udp/%s (subnet %s)",
            self.segment.id,
            self.listener.bound_port,
            self.segment.subnet,
        )

    def datagram_received(self, data: bytes, addr) -> None:
        self.cache.note_packet()
        try:
            record = parse_packet(data)
        except PacketError as exc:
            self.cache.note_malformed()
            log.warning(
                "segment %s: dropping malformed packet from %s: %s",
                self.segment.id,
                addr,
                exc,
            )
            return

        header = record.header
        if not header.qr or header.opcode != 0 or header.rcode != 0:
            # Queries, non-standard opcodes and error responses are not
            # announcements and must not touch the cache.
            self.cache.note_ignored()
            log.debug(
                "segment %s: ignoring non-response packet from %s "
                "(qr=%s opcode=%s rcode=%s)",
                self.segment.id,
                addr,
                header.qr,
                header.opcode,
                header.rcode,
            )
            return

        parsed, unsupported = extract_parsed_records(record)
        result = self.cache.ingest(
            parsed,
            self.segment.id,
            unsupported=unsupported,
            source=f"{addr[0]}:{addr[1]}",
        )
        self.counter["packets"] += 1
        log.info(
            "segment %s: from %s accepted=%d goodbye_applied=%d flushed=%d "
            "unsupported=%d",
            self.segment.id,
            addr[0],
            result.accepted,
            result.goodbyes,
            result.flushed,
            result.unsupported,
        )

    def error_received(self, exc: Exception) -> None:
        log.warning("segment %s: udp error: %s", self.segment.id, exc)


def _make_socket(
    settings: Settings, segment: SegmentConfig
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Broadcast responses are useful for ad-hoc LAN tests; harmless here.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((settings.bind_host, segment.port))
    if settings.join_multicast:
        try:
            group = socket.inet_aton(settings.multicast_group)
            interface = socket.inet_aton(settings.multicast_interface)
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                group + interface,
            )
        except OSError as exc:  # pragma: no cover - depends on host setup
            log.warning(
                "segment %s: could not join %s on %s: %s",
                segment.id,
                settings.multicast_group,
                settings.multicast_interface,
                exc,
            )
        else:
            log.info(
                "segment %s: joined multicast %s on %s",
                segment.id,
                settings.multicast_group,
                settings.multicast_interface,
            )
    sock.setblocking(False)
    return sock


class ListenerManager:
    def __init__(self, settings: Settings, cache) -> None:
        self.settings = settings
        self.cache = cache
        self.listeners: dict[str, SegmentListener] = {}
        self._transports: list[asyncio.DatagramTransport] = []
        self._protocols: list[_Protocol] = []

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        for segment in self.settings.segments:
            sock = _make_socket(self.settings, segment)
            listener = SegmentListener(config=segment)
            protocol = _Protocol(cache=self.cache, segment=segment, listener=listener)
            transport, _ = await loop.create_datagram_endpoint(
                lambda p=protocol: p, sock=sock
            )
            self.listeners[segment.id] = listener
            self._transports.append(transport)  # type: ignore[arg-type]
            self._protocols.append(protocol)

    def bound_port(self, segment_id: str) -> int | None:
        listener = self.listeners.get(segment_id)
        return listener.bound_port if listener else None

    def close(self) -> None:
        for transport in self._transports:
            transport.close()
        for listener in self.listeners.values():
            listener.close()
        self._transports.clear()
        self._protocols.clear()
