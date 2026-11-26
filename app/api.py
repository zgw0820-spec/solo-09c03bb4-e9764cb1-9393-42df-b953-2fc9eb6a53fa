"""FastAPI application exposing query/debug endpoints over the mDNS cache."""

from __future__ import annotations

import ipaddress
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .cache import Cache, ServiceView
from .config import Settings
from .listener import ListenerManager
from .mdns import DEFAULT_SERVICE_TYPE, labels_to_fqdn, validate_service_type


class RecordInfo(BaseModel):
    ttl: int
    remaining_ttl: float
    in_grace: bool


class ServiceResult(BaseModel):
    instance: str
    full_name: str
    host: str
    ip: str
    port: int
    remaining_ttl: float
    records: dict[str, RecordInfo]


class QueryResponse(BaseModel):
    segment: str
    subnet: str
    service: str
    count: int
    services: list[ServiceResult]


class EntryInfo(BaseModel):
    segment: str
    name: str
    type: str
    data: str
    ttl: int
    remaining_ttl: float
    in_grace: bool
    announced_ago: float
    source: str | None = None


class SegmentInfo(BaseModel):
    id: str
    subnet: str
    udp_port: int | None


class StatusResponse(BaseModel):
    segments: list[SegmentInfo]
    stats: dict[str, int]
    cache_entries: int


def resolve_segment(settings: Settings, segment: str | None) -> str:
    """Resolve a segment id or subnet literal to a configured segment id."""

    if segment is None or segment == "":
        if len(settings.segments) == 1:
            return settings.segments[0].id
        raise HTTPException(
            status_code=400,
            detail=(
                "segment is required when multiple segments are configured; "
                f"choose one of {[s.id for s in settings.segments]}"
            ),
        )
    by_id = settings.segment(segment)
    if by_id is not None:
        return by_id.id
    try:
        network = ipaddress.ip_network(segment, strict=True)
    except ValueError:
        network = None
    if network is not None and network.version == 4:
        by_subnet = settings.segment_by_subnet(network)
        if by_subnet is not None:
            return by_subnet.id
        raise HTTPException(
            status_code=404,
            detail=f"no configured segment uses subnet {network}",
        )
    raise HTTPException(
        status_code=404,
        detail=(
            f"unknown segment {segment!r}; configured ids: "
            f"{[s.id for s in settings.segments]}"
        ),
    )


def _render(view: ServiceView) -> ServiceResult:
    return ServiceResult(
        instance=view.instance,
        full_name=view.full_name,
        host=view.host,
        ip=view.ip,
        port=view.port,
        remaining_ttl=view.remaining_ttl,
        records={
            key: RecordInfo(
                ttl=record.ttl,
                remaining_ttl=record.remaining_ttl,
                in_grace=record.in_grace,
            )
            for key, record in view.records.items()
        },
    )


def create_app(
    settings: Settings | None = None,
    cache: Cache | None = None,
    *,
    start_listeners: bool = True,
) -> FastAPI:
    settings = settings or Settings.from_env()
    cache = cache or Cache(max_records=settings.cache_max_records)
    manager = ListenerManager(settings, cache)

    def lifespan_factory():
        @asynccontextmanager
        async def lifespan(_app: FastAPI):
            if start_listeners:
                await manager.start()
            try:
                yield
            finally:
                manager.close()

        return lifespan

    app = FastAPI(
        title="Station mDNS Discovery",
        version="1.0.0",
        description=(
            "Per-segment mDNS responder cache for printer discovery. "
            "Each UDP listener port simulates one network segment."
        ),
        lifespan=lifespan_factory(),
    )
    app.state.settings = settings
    app.state.cache = cache
    app.state.manager = manager

    @app.get("/api/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "segments": [s.id for s in settings.segments]}

    @app.get("/api/status", response_model=StatusResponse)
    def status() -> StatusResponse:
        segments = [
            SegmentInfo(
                id=segment.id,
                subnet=segment.subnet,
                udp_port=manager.bound_port(segment.id) or segment.port or None,
            )
            for segment in settings.segments
        ]
        stats = cache.stats()
        return StatusResponse(
            segments=segments,
            stats=vars(stats),
            cache_entries=len(cache.snapshot()),
        )

    @app.get(
        "/api/segments/{segment}/services",
        response_model=QueryResponse,
    )
    def query_services(
        segment: str,
        service: str = Query(
            DEFAULT_SERVICE_TYPE,
            description="DNS-SD service type, e.g. _ipp._tcp.local.",
        ),
    ) -> QueryResponse:
        segment_id = resolve_segment(settings, segment)
        try:
            service_labels = validate_service_type(service)
        except (ValueError, UnicodeEncodeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        resolved = settings.segment(segment_id)
        assert resolved is not None
        views = cache.query_service(segment_id, service_labels)
        return QueryResponse(
            segment=segment_id,
            subnet=resolved.subnet,
            service=labels_to_fqdn(service_labels),
            count=len(views),
            services=[_render(view) for view in views],
        )

    # Query by segment id or subnet literal via query string, e.g.
    # /api/services?segment=10.20.1.0%2F24&service=_ipp._tcp.local.
    @app.get("/api/services", response_model=QueryResponse)
    def query_services_by_selector(
        segment: str = Query(
            ...,
            description="Segment id or subnet in CIDR form (10.20.1.0/24).",
        ),
        service: str = Query(DEFAULT_SERVICE_TYPE),
    ) -> QueryResponse:
        return query_services(segment, service)

    @app.get("/api/segments/{segment}/records", response_model=list[EntryInfo])
    def list_records(segment: str) -> list[EntryInfo]:
        segment_id = resolve_segment(settings, segment)
        return [EntryInfo(**row) for row in cache.snapshot(segment_id)]

    @app.get("/api/records", response_model=list[EntryInfo])
    def list_all_records() -> list[EntryInfo]:
        return [EntryInfo(**row) for row in cache.snapshot()]

    return app
