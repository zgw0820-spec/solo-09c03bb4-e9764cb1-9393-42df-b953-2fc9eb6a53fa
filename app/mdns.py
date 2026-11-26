"""mDNS packet parsing and construction helpers (dnslib based).

Names are kept as tuples of raw label bytes so display preserves the
responder's original case and UTF-8 bytes.  DNS comparisons go through
``fold_labels`` (case-insensitive), never through the display bytes.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Sequence, Union

from dnslib import A, DNSHeader, DNSLabel, DNSRecord, PTR, QTYPE, RR, SRV

TYPE_A = int(QTYPE.A)
TYPE_PTR = int(QTYPE.PTR)
TYPE_SRV = int(QTYPE.SRV)
TYPE_NAMES = {TYPE_A: "A", TYPE_PTR: "PTR", TYPE_SRV: "SRV"}
NAMES_TO_TYPES = {v: k for k, v in TYPE_NAMES.items()}

CLASS_IN = 1
CACHE_FLUSH_MASK = 0x8000
CLASS_MASK = 0x7FFF

DEFAULT_SERVICE_TYPE = "_ipp._tcp.local."

_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class PacketError(ValueError):
    """Raised when a datagram cannot be parsed as a DNS record."""


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

Labels = tuple[bytes, ...]


def fold_labels(label: Union[DNSLabel, Sequence[bytes], bytes]) -> Labels:
    """Return the case-folded form used for all DNS identity comparisons."""

    return tuple(part.lower() for part in normalize_labels(label))


def normalize_labels(label: Union[DNSLabel, Sequence[bytes], bytes]) -> Labels:
    if isinstance(label, DNSLabel):
        raw = label.label
    elif isinstance(label, (bytes, bytearray)):
        raw = bytes(label).rstrip(b".").split(b".")
    else:
        raw = tuple(bytes(part) for part in label)
    return tuple(part for part in raw if part)


def labels_from_text(text: str) -> Labels:
    """Split a dotted name into UTF-8 labels, *without* IDNA conversion.

    dnslib's ``DNSLabel(str)`` applies IDNA, which mangles UTF-8 instance
    names; constructing labels from bytes avoids that.
    """

    text = text.strip()
    if text.endswith("."):
        text = text[:-1]
    if not text:
        return ()
    return tuple(part.encode("utf-8") for part in text.split("."))


def labels_to_text(labels: Sequence[bytes]) -> str:
    return ".".join(part.decode("utf-8", "replace") for part in labels)


def labels_to_fqdn(labels: Sequence[bytes]) -> str:
    return labels_to_text(labels) + "." if labels else "."


def validate_service_type(text: str) -> Labels:
    """Validate an ASCII DNS-SD service type supplied through the HTTP API."""

    text = (text or "").strip()
    if text.endswith("."):
        text = text[:-1]
    if not text:
        raise ValueError("service type must not be empty")
    labels = text.split(".")
    if any(not label for label in labels):
        raise ValueError("service type contains an empty label")
    if not labels[0].startswith("_"):
        raise ValueError(
            f"DNS-SD service type must start with '_' (got {labels[0]!r})"
        )
    total = 1
    for label in labels:
        encoded = label.encode("ascii", "strict")  # raises UnicodeEncodeError
        if len(encoded) > 63:
            raise ValueError(f"label {label!r} exceeds 63 bytes")
        if not _LABEL_RE.match(label):
            raise ValueError(
                f"label {label!r} contains characters outside [A-Za-z0-9_-]"
            )
        total += 1 + len(encoded)
    if total > 255:
        raise ValueError("service type exceeds 255 bytes on the wire")
    return tuple(label.lower().encode("ascii") for label in labels)


def wire_length(labels: Sequence[bytes]) -> int:
    return 1 + sum(1 + len(part) for part in labels)


# ---------------------------------------------------------------------------
# Record model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PtrData:
    target: Labels


@dataclass(frozen=True)
class SrvData:
    priority: int
    weight: int
    port: int
    target: Labels


@dataclass(frozen=True)
class AddressData:
    address: str


RData = Union[PtrData, SrvData, AddressData]


@dataclass(frozen=True)
class ParsedRecord:
    name: Labels
    rtype: int
    ttl: int
    flush: bool
    rdata: RData

    @property
    def type_name(self) -> str:
        return TYPE_NAMES[self.rtype]

    @property
    def folded_name(self) -> Labels:
        return fold_labels(self.name)

    @property
    def rdata_key(self) -> tuple:
        return fold_rdata(self.rdata)


def fold_rdata(rdata: RData) -> tuple:
    """Case-folded identity of an rdata value (DNS is case-insensitive)."""

    if isinstance(rdata, PtrData):
        return ("ptr", fold_labels(rdata.target))
    if isinstance(rdata, SrvData):
        return (
            "srv",
            rdata.priority,
            rdata.weight,
            rdata.port,
            fold_labels(rdata.target),
        )
    if isinstance(rdata, AddressData):
        return ("a", rdata.address)
    raise TypeError(f"unsupported rdata {rdata!r}")


def parse_rr(rr: RR) -> ParsedRecord | None:
    """Convert a dnslib RR to a ParsedRecord, or None if unsupported.

    Only class IN PTR/SRV/A records are accepted; the cache-flush bit is
    stripped from the class and exposed separately.
    """

    try:
        rclass = int(rr.rclass)
        rtype = int(rr.rtype)
    except (TypeError, ValueError):
        return None
    if (rclass & CLASS_MASK) != CLASS_IN:
        return None
    name = normalize_labels(rr.rname)
    if not name:
        return None
    flush = bool(rclass & CACHE_FLUSH_MASK)
    try:
        ttl = int(rr.ttl)
    except (TypeError, ValueError):
        return None
    if ttl < 0:
        return None

    if rtype == TYPE_PTR:
        target = normalize_labels(rr.rdata.label)
        if not target:
            return None
        return ParsedRecord(name, rtype, ttl, flush, PtrData(target))
    if rtype == TYPE_SRV:
        target = normalize_labels(rr.rdata.target)
        if not target:
            return None
        port = int(rr.rdata.port)
        priority = int(rr.rdata.priority)
        weight = int(rr.rdata.weight)
        if not (0 <= port <= 65535):
            return None
        return ParsedRecord(
            name, rtype, ttl, flush, SrvData(priority, weight, port, target)
        )
    if rtype == TYPE_A:
        raw = bytes(rr.rdata.data)
        if len(raw) != 4:
            return None
        return ParsedRecord(
            name, rtype, ttl, flush, AddressData(str(ipaddress.IPv4Address(raw)))
        )
    return None


def extract_parsed_records(
    record: DNSRecord,
) -> tuple[list[ParsedRecord], int]:
    """Parse all sections of a response.

    Returns ``(records, unsupported_count)``.  Malformed individual records
    (as opposed to a malformed packet header) are counted as unsupported.
    """

    parsed: list[ParsedRecord] = []
    unsupported = 0
    for rr in list(record.rr) + list(record.auth) + list(record.ar):
        item = parse_rr(rr)
        if item is None:
            unsupported += 1
        else:
            parsed.append(item)
    return parsed, unsupported


def parse_packet(data: bytes) -> DNSRecord:
    if not data:
        raise PacketError("empty datagram")
    try:
        record = DNSRecord.parse(data)
    except Exception as exc:  # dnslib raises DNSError/BufferError/struct errors
        raise PacketError(f"malformed DNS packet: {exc}") from exc
    return record


# ---------------------------------------------------------------------------
# Construction (used by samples and tests)
# ---------------------------------------------------------------------------


def _label(labels: Sequence[bytes]) -> DNSLabel:
    return DNSLabel(tuple(bytes(part) for part in labels))


def _rclass(flush: bool) -> int:
    return CLASS_IN | CACHE_FLUSH_MASK if flush else CLASS_IN


def make_ptr(
    service: Sequence[bytes], instance_full: Sequence[bytes], ttl: int, flush: bool = False
) -> RR:
    return RR(
        _label(service),
        TYPE_PTR,
        rclass=_rclass(flush),
        ttl=ttl,
        rdata=PTR(_label(instance_full)),
    )


def make_srv(
    instance_full: Sequence[bytes],
    target: Sequence[bytes],
    port: int,
    ttl: int,
    flush: bool = True,
    priority: int = 0,
    weight: int = 0,
) -> RR:
    return RR(
        _label(instance_full),
        TYPE_SRV,
        rclass=_rclass(flush),
        ttl=ttl,
        rdata=SRV(priority, weight, port, _label(target)),
    )


def make_a(host: Sequence[bytes], address: str, ttl: int, flush: bool = True) -> RR:
    return RR(
        _label(host),
        TYPE_A,
        rclass=_rclass(flush),
        ttl=ttl,
        rdata=A(address),
    )


def service_records(
    *,
    instance: str,
    address: str,
    service: str = DEFAULT_SERVICE_TYPE,
    target: str = "printer.local.",
    port: int = 631,
    ptr_ttl: int = 4500,
    srv_ttl: int = 120,
    a_ttl: int = 120,
    flush: bool = True,
    ttl_override: int | None = None,
) -> list[RR]:
    """Build the PTR/SRV/A trio for one IPP instance.

    ``ttl_override=0`` produces a goodbye packet.  Unique records (SRV/A)
    carry the cache-flush bit by default, as real responders do; the shared
    PTR does not.
    """

    service_labels = validate_service_type(service)
    instance_labels = labels_from_text(instance)
    if not instance_labels:
        raise ValueError("instance name must not be empty")
    full_instance = instance_labels + service_labels
    target_labels = labels_from_text(target)
    if not target_labels:
        raise ValueError("target host must not be empty")
    if ttl_override is None:
        ptr_value, srv_value, a_value = ptr_ttl, srv_ttl, a_ttl
    else:
        ptr_value = srv_value = a_value = ttl_override
        if ttl_override < 0:
            raise ValueError("ttl must be non-negative")
    return [
        make_ptr(service_labels, full_instance, ptr_value, flush=False),
        make_srv(full_instance, target_labels, port, srv_value, flush=flush),
        make_a(target_labels, address, a_value, flush=flush),
    ]


def pack_records(records: Iterable[RR], *, qr: bool = True) -> bytes:
    record = DNSRecord(
        DNSHeader(id=0, qr=1 if qr else 0, aa=1 if qr else 0, opcode=0),
        rr=list(records),
    )
    return record.pack()


def describe_rr(rr: RR) -> str:
    parsed = parse_rr(rr)
    if parsed is None:
        return f"<unsupported {rr.rtype} {rr.rname}>"
    if isinstance(parsed.rdata, PtrData):
        detail = labels_to_fqdn(parsed.rdata.target)
    elif isinstance(parsed.rdata, SrvData):
        detail = (
            f"{parsed.rdata.target and labels_to_fqdn(parsed.rdata.target)} "
            f"port={parsed.rdata.port}"
        )
    else:
        detail = parsed.rdata.address
    return (
        f"{labels_to_fqdn(parsed.name)} {parsed.type_name} ttl={parsed.ttl} "
        f"flush={parsed.flush} -> {detail}"
    )
