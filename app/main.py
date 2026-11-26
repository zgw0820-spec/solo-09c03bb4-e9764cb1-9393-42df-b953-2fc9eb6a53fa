"""Entry point: ``uvicorn app.main:app`` (or ``python -m app.main``)."""

from __future__ import annotations

import logging

import uvicorn

from .api import create_app
from .cache import Cache
from .config import Settings

log = logging.getLogger(__name__)


def build() -> tuple[object, Settings]:
    settings = Settings.from_env()
    cache = Cache(max_records=settings.cache_max_records)
    return create_app(settings=settings, cache=cache), settings


app, settings = build()


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info(
        "starting with segments: %s",
        ", ".join(f"{s.id} udp/{s.port} {s.subnet}" for s in settings.segments),
    )
    uvicorn.run(
        app,
        host=settings.http_host,
        port=settings.http_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
