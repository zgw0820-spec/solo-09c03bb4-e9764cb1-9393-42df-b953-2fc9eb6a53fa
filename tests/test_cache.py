from __future__ import annotations

from app.cache import Cache, GRACE_SECONDS
from app.mdns import (
    extract_parsed_records,
    labels_from_text,
    make_a,
    make_ptr,
    make_srv,
    pack_records,
    parse_packet,
    service_records,
)

SEG_A = "station-a"
SEG_B = "station-b"
IPP = labels_from_text("_ipp._tcp.local.")


def ingest_packet(cache: Cache, payload: bytes, segment: str, now=None):
    record = parse_packet(payload)
    parsed, unsupported = extract_parsed_records(record)
    return cache.ingest(parsed, segment, unsupported=unsupported, now=now)


def announce(instance="Front Desk", address="10.20.1.10", **kwargs) -> bytes:
    return pack_records(service_records(instance=instance, address=address, **kwargs))


def q(cache: Cache, segment=SEG_A, now=None, service=IPP):
    return cache.query_service(segment, service, now=now)


def test_basic_assembly_and_min_ttl(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(ptr_ttl=4500, srv_ttl=300, a_ttl=120), SEG_A, now=clock())
    views = q(cache, now=clock())
    assert len(views) == 1
    view = views[0]
    assert view.instance == "Front Desk"
    assert (view.ip, view.port) == ("10.20.1.10", 631)
    assert view.remaining_ttl == 120.0  # min(4500, 300, 120)
    assert set(view.records) == {"ptr", "srv", "a"}

    clock.advance(100)
    view = q(cache, now=clock())[0]
    assert view.remaining_ttl == 20.0
    assert view.records["ptr"].remaining_ttl == 4400.0


def test_ttl_expiry_breaks_chain(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(a_ttl=10, srv_ttl=300, ptr_ttl=300), SEG_A, now=clock())
    clock.advance(10)
    assert q(cache, now=clock()) == []
    # PTR and SRV remain cached; only the A record expired.
    snapshot = cache.snapshot(SEG_A)
    assert {row["type"] for row in snapshot} == {"PTR", "SRV"}


def test_incomplete_chain_is_not_returned(clock):
    cache = Cache(clock=clock)
    ptr = make_ptr(IPP, labels_from_text("Lonely._ipp._tcp.local."), 120)
    ingest_packet(cache, pack_records([ptr]), SEG_A, now=clock())
    assert q(cache, now=clock()) == []

    # SRV without PTR also does not surface.
    srv = make_srv(
        labels_from_text("Other._ipp._tcp.local."),
        labels_from_text("printer.local."),
        631,
        120,
    )
    ingest_packet(cache, pack_records([srv]), SEG_A, now=clock())
    assert q(cache, now=clock()) == []


def test_records_from_other_segment_are_never_mixed(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    # Only PTR+SRV arrive on segment B: no A, so B must return nothing.
    recs = service_records(instance="Front Desk", address="10.20.2.10")
    ingest_packet(cache, pack_records(recs[:2]), SEG_B, now=clock())
    assert q(cache, SEG_A, now=clock())[0].ip == "10.20.1.10"
    assert q(cache, SEG_B, now=clock()) == []

    ingest_packet(cache, announce(address="10.20.2.10"), SEG_B, now=clock())
    assert q(cache, SEG_B, now=clock())[0].ip == "10.20.2.10"
    assert q(cache, SEG_A, now=clock())[0].ip == "10.20.1.10"


def test_same_name_same_ip_on_two_segments_stays_isolated(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    ingest_packet(cache, announce(address="10.20.2.10"), SEG_B, now=clock())
    # A flush + goodbye for the segment A copy must not affect segment B.
    goodbye = pack_records(service_records(instance="Front Desk", address="10.20.1.10", ttl_override=0))
    ingest_packet(cache, goodbye, SEG_A, now=clock())
    clock.advance(GRACE_SECONDS + 0.01)
    assert q(cache, SEG_A, now=clock()) == []
    b = q(cache, SEG_B, now=clock())
    assert len(b) == 1 and b[0].ip == "10.20.2.10"


# -- fragmented / split-packet refresh ---------------------------------------


def test_fragmented_announcement_reassembles(clock):
    cache = Cache(clock=clock)
    recs = service_records(instance="Front Desk", address="10.20.1.10")
    ingest_packet(cache, pack_records([recs[0]]), SEG_A, now=clock())
    clock.advance(0.2)
    ingest_packet(cache, pack_records([recs[1]]), SEG_A, now=clock())
    clock.advance(0.2)
    ingest_packet(cache, pack_records([recs[2]]), SEG_A, now=clock())
    views = q(cache, now=clock())
    assert len(views) == 1
    # Each record has its own TTL clock; min at this point is ~119.6.
    assert 119.0 < views[0].remaining_ttl <= 120.0


def test_split_refresh_does_not_flush_other_records(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(5)
    old = q(cache, now=clock())[0]
    assert old.remaining_ttl == 115.0

    # Refresher sends PTR first (flush=False), then SRV, then A in separate
    # packets. Each flush must leave the not-yet-reannounced records alive.
    recs = service_records(instance="Front Desk", address="10.20.1.10")
    for rr in recs:
        clock.advance(0.1)
        ingest_packet(cache, pack_records([rr]), SEG_A, now=clock())
        view = q(cache, now=clock())[0]
        assert view.remaining_ttl > 100.0
    # PTR was refreshed first, so it now has the smallest remaining TTL.
    assert q(cache, now=clock())[0].remaining_ttl == 119.9


def test_flush_only_applies_to_stale_records(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())

    # A new address arrives 5s later with the cache-flush bit. Old A is
    # stale and gets one second of grace; PTR/SRV are untouched.
    clock.advance(5)
    new_a = make_a(labels_from_text("printer.local."), "10.20.1.99", 120, flush=True)
    ingest_packet(cache, pack_records([new_a]), SEG_A, now=clock())

    # Both addresses are visible during grace (queries still work).
    ips = {v.ip for v in q(cache, now=clock())}
    assert ips == {"10.20.1.10", "10.20.1.99"}
    assert q(cache, now=clock())[0].records["a"].in_grace is True

    clock.advance(GRACE_SECONDS - 0.01)
    assert len(q(cache, now=clock())) == 2
    clock.advance(0.02)
    assert {v.ip for v in q(cache, now=clock())} == {"10.20.1.99"}
    # PTR/SRV were never flushed.
    assert cache.snapshot(SEG_A) and all(
        row["type"] in {"PTR", "SRV", "A"} for row in cache.snapshot(SEG_A)
    )


def test_flush_does_not_touch_freshly_announced_entry(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(0.5)
    new_a = make_a(labels_from_text("printer.local."), "10.20.1.99", 120, flush=True)
    ingest_packet(cache, pack_records([new_a]), SEG_A, now=clock())
    # The 0.5s-old A record is "too fresh"; it must not enter grace.
    clock.advance(0.6)
    ips = {v.ip for v in q(cache, now=clock())}
    assert ips == {"10.20.1.10", "10.20.1.99"}
    for view in q(cache, now=clock()):
        assert view.records["a"].in_grace is False


def test_flush_boundary_just_over_one_second(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(1.0)  # exactly one second: not yet flushable
    new_a = make_a(labels_from_text("printer.local."), "10.20.1.99", 120, flush=True)
    ingest_packet(cache, pack_records([new_a]), SEG_A, now=clock())
    assert len(q(cache, now=clock())) == 2

    cache2 = Cache(clock=clock)
    ingest_packet(cache2, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(1.001)
    ingest_packet(cache2, pack_records([new_a]), SEG_A, now=clock())
    assert len(q(cache2, now=clock())) == 2  # still both during grace
    clock.advance(1.0)
    assert {v.ip for v in q(cache2, now=clock())} == {"10.20.1.99"}


def test_flush_in_same_packet_protects_its_own_records(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(5)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    assert q(cache, now=clock())[0].records["a"].in_grace is False
    assert q(cache, now=clock())[0].remaining_ttl == 120.0


# -- goodbye ----------------------------------------------------------------


def test_goodbye_grace_then_disappear(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(10)
    goodbye = pack_records(service_records(instance="Front Desk", address="10.20.1.10", ttl_override=0))
    result = ingest_packet(cache, goodbye, SEG_A, now=clock())
    assert result.goodbyes == 3

    view = q(cache, now=clock())[0]
    assert view.remaining_ttl == 1.0
    assert all(record.in_grace for record in view.records.values())

    clock.advance(0.99)
    assert len(q(cache, now=clock())) == 1
    clock.advance(0.02)
    assert q(cache, now=clock()) == []


def test_goodbye_only_matches_exact_record(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(5)
    # Goodbye for a different address on the same host name.
    other = pack_records(
        service_records(instance="Front Desk", address="10.20.1.77", ttl_override=0)
    )
    ingest_packet(cache, other, SEG_A, now=clock())
    # PTR/SRV targets are the same, so those exact records do get goodbye'd;
    # the A record for .10 is not the one in the goodbye and must survive.
    clock.advance(GRACE_SECONDS + 0.01)
    snapshot = cache.snapshot(SEG_A)
    assert [(row["type"], row["data"]) for row in snapshot] == [("A", "10.20.1.10")]


def test_goodbye_does_not_create_entries(clock):
    cache = Cache(clock=clock)
    goodbye = pack_records(service_records(instance="Ghost", address="10.20.1.10", ttl_override=0))
    ingest_packet(cache, goodbye, SEG_A, now=clock())
    assert cache.snapshot() == []
    assert q(cache, now=clock()) == []


def test_goodbye_never_flushes_siblings(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    ingest_packet(cache, announce(instance="Back Desk", address="10.20.1.11"), SEG_A, now=clock())
    clock.advance(5)
    # Goodbye for one host's A record, carrying the cache-flush bit too.
    goodbye_a = make_a(labels_from_text("printer.local."), "10.20.1.10", 0, flush=True)
    ingest_packet(cache, pack_records([goodbye_a]), SEG_A, now=clock())
    clock.advance(GRACE_SECONDS + 0.01)
    # The other host's A record is untouched.
    remaining = {(row["type"], row["data"]) for row in cache.snapshot(SEG_A)}
    assert ("A", "10.20.1.11") in remaining


def test_positive_reannounce_during_grace_renews(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(10)
    goodbye = pack_records(service_records(instance="Front Desk", address="10.20.1.10", ttl_override=0))
    ingest_packet(cache, goodbye, SEG_A, now=clock())
    clock.advance(0.5)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(2)
    view = q(cache, now=clock())
    assert len(view) == 1
    assert view[0].remaining_ttl == 118.0
    assert view[0].records["a"].in_grace is False


def test_positive_reannounce_cancels_pending_flush(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(5)
    # New A triggers flush grace on the old one...
    new_a = make_a(labels_from_text("printer.local."), "10.20.1.99", 120, flush=True)
    ingest_packet(cache, pack_records([new_a]), SEG_A, now=clock())
    clock.advance(0.5)
    # ...then the old address is re-announced with a positive TTL.
    old_a = make_a(labels_from_text("printer.local."), "10.20.1.10", 120, flush=True)
    ingest_packet(cache, pack_records([old_a]), SEG_A, now=clock())
    clock.advance(2)
    ips = {v.ip for v in q(cache, now=clock())}
    assert ips == {"10.20.1.10", "10.20.1.99"}


def test_same_packet_positive_wins_over_goodbye(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(5)
    a0 = make_a(labels_from_text("printer.local."), "10.20.1.10", 0, flush=True)
    a120 = make_a(labels_from_text("printer.local."), "10.20.1.10", 120, flush=True)
    ingest_packet(cache, pack_records([a0, a120]), SEG_A, now=clock())
    view = q(cache, now=clock())[0]
    assert view.records["a"].in_grace is False
    assert view.records["a"].remaining_ttl == 120.0
    # PTR/SRV from the original announcement were not touched by this packet.
    assert view.records["ptr"].remaining_ttl == 4495.0


# -- filtering and hygiene --------------------------------------------------


def test_expired_entries_are_purged_and_not_queryable(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10", a_ttl=1, srv_ttl=1, ptr_ttl=1), SEG_A, now=clock())
    clock.advance(GRACE_SECONDS + 0.5)
    assert cache.query_service(SEG_A, IPP, now=clock()) == []
    assert cache.snapshot(SEG_A) == []


def test_case_insensitive_cache_keys_but_display_case_kept(clock):
    cache = Cache(clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    views = cache.query_service(SEG_A, labels_from_text("_IPP._TCP.local."), now=clock())
    assert len(views) == 1
    assert views[0].instance == "Front Desk"


def test_multiple_addresses_for_one_srv(clock):
    cache = Cache(clock=clock)
    recs = service_records(instance="Front Desk", address="10.20.1.10")
    other_a = make_a(labels_from_text("printer.local."), "10.20.1.11", 120, flush=True)
    ingest_packet(cache, pack_records(recs + [other_a]), SEG_A, now=clock())
    views = q(cache, now=clock())
    assert [v.ip for v in views] == ["10.20.1.10", "10.20.1.11"]


def test_capacity_eviction(clock):
    cache = Cache(max_records=2, clock=clock)
    ingest_packet(cache, announce(address="10.20.1.10"), SEG_A, now=clock())
    clock.advance(1)
    ingest_packet(cache, announce(instance="Two", address="10.20.1.12"), SEG_A, now=clock())
    assert len(cache.snapshot()) <= 2
    assert cache.stats().entries_evicted >= 1
