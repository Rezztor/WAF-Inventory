"""Vendor-neutral data model (SQLAlchemy 2). SQLite by default, any SQLAlchemy URL works."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import JSON, ForeignKey, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "source"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    kind: Mapped[str]
    status: Mapped[str] = mapped_column(default="never run")
    error: Mapped[str | None]
    last_run: Mapped[datetime | None]
    gateways: Mapped[list[Gateway]] = relationship(back_populates="source", cascade="all, delete-orphan")
    policies: Mapped[list[WafPolicy]] = relationship(back_populates="source", cascade="all, delete-orphan")
    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="source", cascade="all, delete-orphan")


class Gateway(Base):
    """An App Gateway, a Front Door profile or a BIG-IP device."""
    __tablename__ = "gateway"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id"))
    vendor: Mapped[str]
    kind: Mapped[str]  # appgw | afd | bigip
    name: Mapped[str]
    native_id: Mapped[str | None]
    version: Mapped[str | None]
    location: Mapped[str | None]
    source: Mapped[Source] = relationship(back_populates="gateways")
    listeners: Mapped[list[Listener]] = relationship(back_populates="gateway", cascade="all, delete-orphan")


class WafPolicy(Base):
    __tablename__ = "waf_policy"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id"))
    vendor: Mapped[str]
    name: Mapped[str]
    native_id: Mapped[str | None]
    mode: Mapped[str]  # block | detect | off | unknown
    settings: Mapped[dict] = mapped_column(JSON, default=dict)  # normalized, see README "Policy settings"
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_hash: Mapped[str] = mapped_column(default="")
    source: Mapped[Source] = relationship(back_populates="policies")

    def __init__(self, **kw):
        super().__init__(**kw)
        self.raw_hash = hashlib.sha256(json.dumps(self.raw or {}, sort_keys=True).encode()).hexdigest()


class Listener(Base):
    """AppGW listener, AFD domain or F5 virtual server."""
    __tablename__ = "listener"
    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_id: Mapped[int] = mapped_column(ForeignKey("gateway.id"))
    name: Mapped[str]
    protocol: Mapped[str]  # http | https | tcp | tls ...
    address: Mapped[str | None]
    port: Mapped[int | None]
    hostnames: Mapped[list] = mapped_column(JSON, default=list)
    waf_capable: Mapped[bool] = mapped_column(default=True)  # False for L4 listeners / non-HTTP virtual servers
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("waf_policy.id"))
    native_id: Mapped[str | None]
    gateway: Mapped[Gateway] = relationship(back_populates="listeners")
    policy: Mapped[WafPolicy | None] = relationship()
    routes: Mapped[list[Route]] = relationship(back_populates="listener", cascade="all, delete-orphan")


class Route(Base):
    """Path rule / AFD route / LTM policy rule. Empty `hosts` means all listener hostnames."""
    __tablename__ = "route"
    id: Mapped[int] = mapped_column(primary_key=True)
    listener_id: Mapped[int] = mapped_column(ForeignKey("listener.id"))
    name: Mapped[str]
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    paths: Mapped[list] = mapped_column(JSON, default=list)  # glob patterns, e.g. /api/*
    backend: Mapped[dict | None] = mapped_column(JSON)  # {"name": ..., "members": [...]}
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("waf_policy.id"))
    listener: Mapped[Listener] = relationship(back_populates="routes")
    policy: Mapped[WafPolicy | None] = relationship()


class Endpoint(Base):
    __tablename__ = "endpoint"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id"))
    host: Mapped[str]
    method: Mapped[str]
    template: Mapped[str]
    kind: Mapped[str]  # api | web | static | ws | unknown
    confidence: Mapped[float]
    confirmed: Mapped[bool]  # hits >= evidence floor
    hits: Mapped[int]
    first_seen: Mapped[str | None]
    last_seen: Mapped[str | None]
    statuses: Mapped[dict] = mapped_column(JSON, default=dict)
    content_types: Mapped[list] = mapped_column(JSON, default=list)
    query_params: Mapped[list] = mapped_column(JSON, default=list)
    path_params: Mapped[dict] = mapped_column(JSON, default=dict)  # name -> type
    samples: Mapped[list] = mapped_column(JSON, default=list)  # a few raw paths, query stripped
    source: Mapped[Source] = relationship(back_populates="endpoints")


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule: Mapped[str]
    severity: Mapped[str]  # high | medium | low
    title: Mapped[str]
    subject: Mapped[str]
    detail: Mapped[str]


def connect(url: str) -> Session:
    if "://" not in url:
        url = f"sqlite:///{url}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return Session(engine)


def source(session: Session, name: str, kind: str) -> Source:
    src = session.query(Source).filter_by(name=name).one_or_none()
    if src is None:
        src = Source(name=name, kind=kind)
        session.add(src)
    return src


def save_snapshot(session: Session, name: str, kind: str, gateways: list[Gateway], policies: list[WafPolicy]) -> Source:
    """Replace a source's config (gateways, listeners, routes, policies) with a fresh snapshot."""
    src = source(session, name, kind)
    src.gateways = []
    src.policies = []
    session.flush()
    src.gateways = gateways
    src.policies = policies
    src.status, src.error, src.last_run = "ok", None, now()
    session.commit()
    return src


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
