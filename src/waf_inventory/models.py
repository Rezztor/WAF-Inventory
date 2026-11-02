"""Vendor-neutral data model (SQLAlchemy 2). SQLite by default, any SQLAlchemy URL works."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import JSON, ForeignKey, UniqueConstraint, create_engine
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
    events: Mapped[list[WafEvent]] = relationship(cascade="all, delete-orphan")


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


class WafEvent(Base):
    """A request a WAF rule matched (Baffin Bay), kept for tuning. Of the headers only Host and User-Agent are kept."""
    __tablename__ = "waf_event"
    id: Mapped[str] = mapped_column(primary_key=True)  # the vendor's event id
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id"), index=True)
    time: Mapped[str] = mapped_column(index=True)  # ISO 8601, UTC
    proxy: Mapped[str | None]  # the vendor's id of the proxy (= WafPolicy.native_id)
    host: Mapped[str]
    method: Mapped[str | None]
    path: Mapped[str]  # query string dropped
    status: Mapped[int | None]  # what the client got: the WAF's 403 when blocked, the application's answer when only logged
    action: Mapped[str | None]  # BLOCKED | LOGGED
    instance: Mapped[str] = mapped_column(default="main")  # main | staging
    rules: Mapped[list] = mapped_column(JSON, default=list)  # [{"id": "942100", "name": ...}]
    matched: Mapped[list] = mapped_column(JSON, default=list)  # matched data, when the proxy records it
    source_ip: Mapped[str | None]
    country: Mapped[str | None]
    user_agent: Mapped[str | None]
    support_id: Mapped[str | None] = mapped_column(index=True)


class TuningDecision(Base):
    """An administrator's answer to one tuning proposal, keyed by proxy + rule + path template."""
    __tablename__ = "tuning_decision"
    key: Mapped[str] = mapped_column(primary_key=True)
    decision: Mapped[str]  # approved | rejected
    user: Mapped[str | None]
    time: Mapped[datetime]


class Change(Base):
    """One difference between a source's previous snapshot and the new one."""
    __tablename__ = "change"
    id: Mapped[int] = mapped_column(primary_key=True)
    time: Mapped[datetime] = mapped_column(index=True)
    source: Mapped[str]
    kind: Mapped[str]  # added | removed | changed
    what: Mapped[str]  # listener | route | policy
    subject: Mapped[str]
    detail: Mapped[str] = mapped_column(default="")
    weakened: Mapped[bool] = mapped_column(default=False)  # blocking turned off, or a WAF policy taken away


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule: Mapped[str]
    severity: Mapped[str]  # high | medium | low
    title: Mapped[str]
    subject: Mapped[str]
    detail: Mapped[str]


class User(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str]
    role: Mapped[str] = mapped_column(default="admin")
    last_login: Mapped[datetime | None]


class LoginSession(Base):
    """Server-side session; the cookie holds a random token, only its SHA-256 is stored."""
    __tablename__ = "login_session"
    id: Mapped[str] = mapped_column(primary_key=True)  # sha256(token)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    csrf: Mapped[str]
    created: Mapped[datetime]
    last_seen: Mapped[datetime]
    ip: Mapped[str | None]
    user_agent: Mapped[str | None]
    user: Mapped[User] = relationship()


class SourceConfig(Base):
    """A source managed in the console. Non-secret settings only; credentials live in `secret`."""
    __tablename__ = "source_config"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    type: Mapped[str]
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    secrets: Mapped[list[Secret]] = relationship(cascade="all, delete-orphan")


class Secret(Base):
    __tablename__ = "secret"
    __table_args__ = (UniqueConstraint("source_config_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_config_id: Mapped[int] = mapped_column(ForeignKey("source_config.id"))
    kind: Mapped[str]  # password | client_secret | certificate
    token: Mapped[str]  # Fernet token under the master key
    meta: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. thumbprint, expiry, public certificate
    updated: Mapped[datetime]


class Job(Base):
    __tablename__ = "job"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str]
    trigger: Mapped[str] = mapped_column(default="manual")
    status: Mapped[str] = mapped_column(default="queued")  # queued | running | ok | error
    created: Mapped[datetime]
    started: Mapped[datetime | None]
    finished: Mapped[datetime | None]
    summary: Mapped[str | None]
    log: Mapped[str] = mapped_column(default="")


class Setting(Base):
    """Console settings that override config.toml, e.g. discovery thresholds."""
    __tablename__ = "setting"
    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class AuditLog(Base):
    """Who changed what. Never holds a secret value."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    time: Mapped[datetime]
    user: Mapped[str | None]
    ip: Mapped[str | None]
    action: Mapped[str]
    target: Mapped[str] = mapped_column(default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


def get_setting(s: Session, key: str, default: dict | None = None) -> dict:
    row = s.get(Setting, key)
    return row.value if row else (default or {})


def put_setting(s: Session, key: str, value: dict) -> None:
    s.merge(Setting(key=key, value=value))


def connect(url: str) -> Session:
    if "://" not in url:
        url = f"sqlite:///{url}"
    sqlite = url.startswith("sqlite")
    engine = create_engine(url, **({"connect_args": {"timeout": 30}} if sqlite else {}))
    if sqlite:
        with engine.connect() as c:
            c.exec_driver_sql("PRAGMA journal_mode=WAL")  # the job thread writes while pages read
    Base.metadata.create_all(engine)
    return Session(engine)


def source(session: Session, name: str, kind: str) -> Source:
    src = session.query(Source).filter_by(name=name).one_or_none()
    if src is None:
        src = Source(name=name, kind=kind)
        session.add(src)
    return src


def save_snapshot(session: Session, name: str, kind: str, gateways: list[Gateway], policies: list[WafPolicy]) -> Source:
    """Replace a source's config (gateways, listeners, routes, policies) with a fresh snapshot, recording what changed."""
    src = source(session, name, kind)
    before = _facts(src) if src.last_run else None  # a first collection is not a change
    src.gateways = []
    src.policies = []
    session.flush()
    src.gateways = gateways
    src.policies = policies
    src.status, src.error, src.last_run = "ok", None, now()
    if before is not None:
        session.add_all(Change(time=src.last_run, source=name, **c) for c in diff(before, _facts(src)))
    session.commit()
    return src


def _facts(src: Source) -> dict[str, dict]:
    """"what|subject" -> the fields a change is reported on. JSON defaults apply only at insert, hence the `or []`."""
    out = {f"policy|{p.vendor}: {p.name}": {"mode": p.mode, **(p.settings or {})} for p in src.policies}
    for g in src.gateways:
        for lst in g.listeners:
            at = f"{g.name} / {lst.name}"
            out[f"listener|{at}"] = {"protocol": lst.protocol, "port": lst.port, "hostnames": lst.hostnames or [],
                                     "waf policy": lst.policy.name if lst.policy else None}
            for r in lst.routes:
                out[f"route|{at} / {r.name}"] = {"hosts": r.hosts or [], "paths": r.paths or [], "backend": r.backend,
                                                 "waf policy": r.policy.name if r.policy else None}
    return out


def _short(v) -> str:
    t = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    return t if len(t) <= 80 else t[:77] + "..."


def diff(before: dict[str, dict], after: dict[str, dict]) -> list[dict]:
    out = []
    for key in sorted(before.keys() | after.keys()):
        what, subject = key.split("|", 1)
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if old is None or new is None:
            out.append({"kind": "added" if old is None else "removed", "what": what, "subject": subject, "detail": "",
                        "weakened": old is not None and what == "policy" and old.get("mode") == "block"})
            continue
        fields = [f for f in sorted(old.keys() | new.keys()) if old.get(f) != new.get(f)]
        out.append({"kind": "changed", "what": what, "subject": subject,
                    "detail": "; ".join(f"{f}: {_short(old.get(f))} → {_short(new.get(f))}" for f in fields),
                    "weakened": (old.get("mode") == "block" and new.get("mode") != "block")
                                or (old.get("waf policy") is not None and new.get("waf policy") is None)})
    return out


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
