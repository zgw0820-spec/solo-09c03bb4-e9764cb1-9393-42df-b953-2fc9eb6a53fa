"""In-memory, per-segment mDNS record cache.

Semantics implemented here (see README for the operator-facing summary):

* Records are cached per segment (one UDP listener port == one segment), so
  identical names on two segments never bleed into each other.
* A positive-TTL record upserts its cache entry: TTL and announcement time
  are refreshed and any pending grace is cancelled ("positive re-announce
  renews").
* Cache-flush records (class bit 0x8000) schedule *other* cached records with
  the same segment/name/type for deletion one second after the packet, but
  only when (a) they were not re-announced by the same packet and (b) their
  last announcement is more than one second old.  Freshly announced records
  are therefore never flushed by a reordered packet.
* TTL=0 "goodbye" records only affect the exactly matching cache record
  (same segment/name/type/rdata) and give it at most one more second.  A
  goodbye never performs a cache-flush sweep, and never creates an entry.
* Entries stay queryable until their (possibly shortened) deadline, so
  queries during the one-second grace still see them.  A positive-TTL
  re-announcement during grace extends the lifetime again.

Time is read through an injectable monotonic clock so the one-second rules
can be tested deterministically.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .mdns import (
    AddressData,
    Labels,
    ParsedRecord,
    PtrData,
    SrvData,
    TYPE_A,
    TYPE_NAMES,
    TYPE_PTR,
    TYPE_SRV,
    fold_labels,
    fold_rdata,
    labels_to_fqdn,
)

GRACE_SECONDS = 1.0
_PURGE_INTERVAL = 0.5


@dataclass(frozen=True)
class EntryKey:
    segment: str
    name: Labels
    rtype: int
    rdata: tuple  # folded rdata identity


@dataclass
class CacheEntry:
    segment: str
    name: Labels
    rtype: int
    rdata: object
    ttl: int
    announced_at: float
    expires_at: float
    grace_until: float | None = None
    source: str | None = None

    def deadline(self) -> float:
        if self.grace_until is None:
            return self.expires_at
        return min(self.expires_at, self.grace_until)

    def valid_at(self, now: float) -> bool:
        return now < self.deadline()

    def remaining(self, now: float) -> float:
        return max(0.0, self.deadline() - now)

    def in_grace_at(self, now: float) -> bool:
        return (
            self.grace_until is not None
            and now < self.grace_until
            and self.grace_until < self.expires_at
        )


@dataclass
class RecordView:
    ttl: int
    remaining_ttl: float
    in_grace: bool


@dataclass
class ServiceView:
    instance: str
    full_name: str
    host: str
    ip: str
    port: int
    remaining_ttl: float
    records: dict[str, RecordView]


@dataclass
class CacheStats:
    packets_received: int = 0
    packets_malformed: int = 0
    packets_ignored: int = 0
    records_seen: int = 0
    records_unsupported: int = 0
    records_accepted: int = 0
    goodbyes_applied: int = 0
    flushes_applied: int = 0
    entries_evicted: int = 0


@dataclass
class IngestResult:
    accepted: int = 0
    goodbyes: int = 0
    flushed: int = 0
    unsupported: int = 0


class Cache:
    def __init__(
        self,
        max_records: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lock = threading.RLock()
        self._clock = clock
        self._max_records = max(1, int(max_records))
        self._entries: dict[EntryKey, CacheEntry] = {}
        self._stats = CacheStats()
        self._next_purge = 0.0

    # -- packet level bookkeeping -----------------------------------------

    def note_packet(self) -> None:
        with self._lock:
            self._stats.packets_received += 1

    def note_malformed(self) -> None:
        with self._lock:
            self._stats.packets_malformed += 1

    def note_ignored(self) -> None:
        with self._lock:
            self._stats.packets_ignored += 1

    def stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(**vars(self._stats))

    # -- ingest ------------------------------------------------------------

    def ingest(
        self,
        records: Sequence[ParsedRecord],
        segment: str,
        *,
        unsupported: int = 0,
        source: str | None = None,
        now: float | None = None,
    ) -> IngestResult:
        with self._lock:
            now = self._clock() if now is None else now
            stats = self._stats
            stats.records_seen += len(records) + unsupported
            stats.records_unsupported += unsupported
            result = IngestResult(unsupported=unsupported)

            positives: list[ParsedRecord] = []
            goodbyes: list[ParsedRecord] = []
            for record in records:
                if record.ttl == 0:
                    goodbyes.append(record)
                else:
                    positives.append(record)

            positives.sort(key=lambda r: (r.name, r.rtype, str(r.rdata)))
            goodbyes.sort(key=lambda r: (r.name, r.rtype, str(r.rdata)))

            # 1. Positive records upsert/renew first; remember their keys so a
            #    contradictory goodbye in the same packet cannot downgrade
            #    them.
            positive_keys: set[EntryKey] = set()
            for record in positives:
                key = self._upsert(record, segment, now, source)
                positive_keys.add(key)
                result.accepted += 1
                stats.records_accepted += 1

            # 2. Goodbyes: exact-match only, never create or sweep.
            for record in goodbyes:
                key = self._key_for(record, segment)
                if key in positive_keys:
                    continue
                self._goodbye(key, now, result)

            # 3. Cache-flush sweep, after renewal so this packet's records are
            #    exempt and old ones get their one-second grace.  TTL=0
            #    records never trigger a sweep.
            swept: set[tuple[Labels, int]] = set()
            for record in positives:
                if not record.flush:
                    continue
                name_type = (record.name, record.rtype)
                if name_type in swept:
                    continue
                swept.add(name_type)
                self._flush_sweep(
                    segment, record.name, record.rtype, positive_keys, now, result
                )

            stats.goodbyes_applied += result.goodbyes
            stats.flushes_applied += result.flushed
            self._maybe_purge(now)
            return result

    def _key_for(self, record: ParsedRecord, segment: str) -> EntryKey:
        return EntryKey(
            segment,
            fold_labels(record.name),
            record.rtype,
            fold_rdata(record.rdata),
        )

    def _upsert(
        self,
        record: ParsedRecord,
        segment: str,
        now: float,
        source: str | None,
    ) -> EntryKey:
        key = self._key_for(record, segment)
        expires_at = now + record.ttl
        existing = self._entries.get(key)
        if existing is not None:
            existing.ttl = record.ttl
            existing.announced_at = now
            existing.expires_at = expires_at
            existing.grace_until = None
            existing.source = source
        else:
            self._ensure_capacity(now)
            self._entries[key] = CacheEntry(
                segment=segment,
                name=record.name,
                rtype=record.rtype,
                rdata=record.rdata,
                ttl=record.ttl,
                announced_at=now,
                expires_at=expires_at,
                source=source,
            )
        return key

    def _goodbye(self, key: EntryKey, now: float, result: IngestResult) -> None:
        entry = self._entries.get(key)
        if entry is None or not entry.valid_at(now):
            return
        self._shorten(entry, now + GRACE_SECONDS)
        result.goodbyes += 1

    def _flush_sweep(
        self,
        segment: str,
        name: Labels,
        rtype: int,
        protected: set[EntryKey],
        now: float,
        result: IngestResult,
    ) -> None:
        for key, entry in self._entries.items():
            if (
                entry.segment != segment
                or fold_labels(entry.name) != fold_labels(name)
                or entry.rtype != rtype
            ):
                continue
            if key in protected:
                continue
            if not entry.valid_at(now):
                continue
            if now - entry.announced_at <= GRACE_SECONDS:
                # Announced less than a second ago: too fresh to be sure the
                # incoming packet really supersedes it.  Leave it alone.
                continue
            self._shorten(entry, now + GRACE_SECONDS)
            result.flushed += 1

    @staticmethod
    def _shorten(entry: CacheEntry, until: float) -> None:
        if entry.grace_until is None or until < entry.grace_until:
            entry.grace_until = until

    def _ensure_capacity(self, now: float) -> None:
        if len(self._entries) < self._max_records:
            return
        self._purge(now)
        if len(self._entries) < self._max_records:
            return
        excess = len(self._entries) - self._max_records + 1
        by_deadline = sorted(
            self._entries.items(), key=lambda item: item[1].deadline()
        )
        for key, _entry in by_deadline[:excess]:
            del self._entries[key]
            self._stats.entries_evicted += 1

    # -- queries -----------------------------------------------------------

    def query_service(
        self,
        segment: str,
        service: Labels,
        *,
        now: float | None = None,
    ) -> list[ServiceView]:
        with self._lock:
            now = self._clock() if now is None else now
            self._purge(now)
            service = fold_labels(service)
            views: list[ServiceView] = []

            ptr_entries = sorted(
                (
                    entry
                    for entry in self._entries.values()
                    if entry.segment == segment
                    and entry.rtype == TYPE_PTR
                    and fold_labels(entry.name) == service
                    and isinstance(entry.rdata, PtrData)
                    and entry.valid_at(now)
                ),
                key=lambda e: fold_labels(e.rdata.target),  # type: ignore[union-attr]
            )

            for ptr in ptr_entries:
                assert isinstance(ptr.rdata, PtrData)
                target = ptr.rdata.target
                # DNS-SD: the PTR target is "<Instance>.<ServiceType>".
                if len(target) != len(service) + 1 or fold_labels(target[1:]) != service:
                    continue
                instance = target[0].decode("utf-8", "replace")
                srv_entries = sorted(
                    (
                        entry
                        for entry in self._entries.values()
                        if entry.segment == segment
                        and entry.rtype == TYPE_SRV
                        and fold_labels(entry.name) == fold_labels(target)
                        and isinstance(entry.rdata, SrvData)
                        and entry.valid_at(now)
                    ),
                    key=lambda e: (  # type: ignore[union-attr]
                        fold_labels(e.rdata.target),
                        e.rdata.port,
                    ),
                )
                for srv in srv_entries:
                    assert isinstance(srv.rdata, SrvData)
                    target_host = fold_labels(srv.rdata.target)
                    a_entries = sorted(
                        (
                            entry
                            for entry in self._entries.values()
                            if entry.segment == segment
                            and entry.rtype == TYPE_A
                            and fold_labels(entry.name) == target_host
                            and isinstance(entry.rdata, AddressData)
                            and entry.valid_at(now)
                        ),
                        key=lambda e: e.rdata.address,  # type: ignore[union-attr]
                    )
                    for a_entry in a_entries:
                        assert isinstance(a_entry.rdata, AddressData)
                        remaining = min(
                            ptr.remaining(now),
                            srv.remaining(now),
                            a_entry.remaining(now),
                        )
                        views.append(
                            ServiceView(
                                instance=instance,
                                full_name=labels_to_fqdn(target),
                                host=labels_to_fqdn(srv.rdata.target),
                                ip=a_entry.rdata.address,
                                port=srv.rdata.port,
                                remaining_ttl=round(remaining, 3),
                                records={
                                    "ptr": _record_view(ptr, now),
                                    "srv": _record_view(srv, now),
                                    "a": _record_view(a_entry, now),
                                },
                            )
                        )
            views.sort(key=lambda v: (v.instance.lower(), v.ip, v.port))
            return views

    def snapshot(self, segment: str | None = None) -> list[dict]:
        """Read-only view of cache entries for debugging/verification."""

        with self._lock:
            now = self._clock()
            entries = [
                entry
                for entry in self._entries.values()
                if entry.valid_at(now) and (segment is None or entry.segment == segment)
            ]
            entries.sort(
                key=lambda e: (e.segment, e.name, e.rtype, str(e.rdata))
            )
            return [
                {
                    "segment": entry.segment,
                    "name": labels_to_fqdn(entry.name),
                    "type": TYPE_NAMES[entry.rtype],
                    "data": _rdata_text(entry.rdata),
                    "ttl": entry.ttl,
                    "remaining_ttl": round(entry.remaining(now), 3),
                    "in_grace": entry.in_grace_at(now),
                    "announced_ago": round(now - entry.announced_at, 3),
                    "source": entry.source,
                }
                for entry in entries
            ]

    # -- maintenance -------------------------------------------------------

    def _maybe_purge(self, now: float) -> None:
        if now >= self._next_purge:
            self._purge(now)
            self._next_purge = now + _PURGE_INTERVAL

    def _purge(self, now: float) -> None:
        expired = [
            key for key, entry in self._entries.items() if not entry.valid_at(now)
        ]
        for key in expired:
            del self._entries[key]


def _record_view(entry: CacheEntry, now: float) -> RecordView:
    return RecordView(
        ttl=entry.ttl,
        remaining_ttl=round(entry.remaining(now), 3),
        in_grace=entry.in_grace_at(now),
    )


def _rdata_text(rdata: object) -> str:
    if isinstance(rdata, PtrData):
        return labels_to_fqdn(rdata.target)
    if isinstance(rdata, SrvData):
        return (
            f"{rdata.priority} {rdata.weight} {rdata.port} "
            f"{labels_to_fqdn(rdata.target)}"
        )
    if isinstance(rdata, AddressData):
        return rdata.address
    return repr(rdata)
