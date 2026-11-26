from __future__ import annotations

import pytest

from app import mdns
from app.mdns import (
    DNSHeader,
    DNSRecord,
    PacketError,
    RR,
    QTYPE,
    A,
    describe_rr,
    extract_parsed_records,
    fold_labels,
    labels_from_text,
    labels_to_fqdn,
    make_a,
    make_ptr,
    pack_records,
    parse_packet,
    service_records,
    validate_service_type,
)


def test_service_records_roundtrip_preserves_instance_case():
    records = service_records(instance="Front Desk", address="10.20.1.10")
    parsed, unsupported = extract_parsed_records(parse_packet(pack_records(records)))
    assert unsupported == 0
    assert [r.rtype for r in parsed] == [12, 33, 1]
    ptr = parsed[0]
    assert labels_to_fqdn(ptr.name) == "_ipp._tcp.local."
    assert labels_to_fqdn(ptr.rdata.target) == "Front Desk._ipp._tcp.local."
    assert ptr.flush is False
    srv = parsed[1]
    assert srv.rdata.port == 631
    assert labels_to_fqdn(srv.rdata.target) == "printer.local."
    assert srv.flush is True


def test_utf8_instance_name_roundtrip():
    records = service_records(instance="前台 打印机", address="10.20.1.11")
    parsed, _ = extract_parsed_records(parse_packet(pack_records(records)))
    assert parsed[0].rdata.target[0].decode("utf-8") == "前台 打印机"


def test_class_high_bit_is_cache_flush_and_class_in():
    rr = make_a(labels_from_text("printer.local."), "10.20.1.10", 120, flush=True)
    wire = pack_records([rr])
    parsed_rr = DNSRecord.parse(wire).rr[0]
    assert parsed_rr.rclass == 0x8001
    parsed, _ = extract_parsed_records(DNSRecord.parse(wire))
    assert parsed[0].flush is True


def test_unknown_class_and_type_are_unsupported():
    unsupported_rr = RR(
        "_ipp._tcp.local.", QTYPE.TXT, rclass=1, ttl=10, rdata=mdns.PTR(
            labels_from_text("x._ipp._tcp.local.")
        )
    )
    parsed, unsupported = extract_parsed_records(
        DNSRecord(DNSHeader(qr=1), rr=[unsupported_rr])
    )
    assert parsed == []
    assert unsupported == 1

    chaOS = RR("printer.local.", QTYPE.A, rclass=3, ttl=10, rdata=A("10.0.0.1"))
    parsed, unsupported = extract_parsed_records(
        DNSRecord(DNSHeader(qr=1), rr=[chaOS])
    )
    assert parsed == []
    assert unsupported == 1


def test_malformed_packet_raises_packet_error():
    with pytest.raises(PacketError):
        parse_packet(b"")
    with pytest.raises(PacketError):
        parse_packet(b"\x00\x01\x02")


def test_fold_is_case_insensitive_but_display_keeps_case():
    labels = labels_from_text("Front Desk._IPP._tcp.local.")
    assert labels == ("Front Desk".encode(), b"_IPP", b"_tcp", b"local")
    assert fold_labels(labels) == (b"front desk", b"_ipp", b"_tcp", b"local")
    assert fold_labels(b"Front Desk._IPP._tcp.local.") == fold_labels(labels)


def test_validate_service_type_rejects_bad_input():
    assert validate_service_type("_ipp._tcp.local.") == (b"_ipp", b"_tcp", b"local")
    for bad in ("", "_ipp..local", "ipp._tcp.local", "_ipp._tcp.local..x", "é._tcp.local"):
        with pytest.raises(ValueError):
            validate_service_type(bad)
    with pytest.raises(UnicodeEncodeError):
        validate_service_type("_ipp._tcp.localé")
    long_label = "a" * 64 + "._tcp.local"
    with pytest.raises(ValueError):
        validate_service_type(long_label)


def test_service_type_too_long_rejected():
    # 4 labels of 63 chars = 256 bytes on the wire including root.
    name = ".".join(["a" * 63] * 4)
    with pytest.raises(ValueError):
        validate_service_type(name)


def test_ttl_zero_goodbye_packet_has_ttl_zero():
    records = service_records(instance="A", address="10.20.1.10", ttl_override=0)
    parsed, _ = extract_parsed_records(parse_packet(pack_records(records)))
    assert all(record.ttl == 0 for record in parsed)


def test_zero_target_records_are_unsupported():
    # A PTR with an empty target cannot be used for assembly and is skipped.
    zero_target = make_ptr(labels_from_text("_ipp._tcp.local."), b"", 10)
    parsed, unsupported = extract_parsed_records(DNSRecord(DNSHeader(qr=1), rr=[zero_target]))
    assert parsed == []
    assert unsupported == 1


def test_query_packet_is_distinguishable():
    query = DNSRecord.question("_ipp._tcp.local.", "PTR")
    parsed = parse_packet(query.pack())
    assert parsed.header.qr == 0


def test_describe_rr_smoke():
    rec = service_records(instance="A", address="10.20.1.10")
    text = "\n".join(describe_rr(rr) for rr in rec)
    assert "PTR" in text and "SRV" in text and "A ttl" in text
