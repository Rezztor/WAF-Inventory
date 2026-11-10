"""Alerts after a collection: weakened protection, new high findings, a failed run, credentials about to expire.

Sent to a webhook (a JSON POST) and by email (SMTP). Nothing is sent until a channel is set under Settings › Alerts.
The webhook URL and the SMTP password are encrypted under the master key, like the connections' credentials.
"""
from __future__ import annotations

import smtplib
import ssl
from collections.abc import Callable
from datetime import date, timedelta
from email.message import EmailMessage
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from . import sources, vault
from .models import Change, FindingState, Job, SourceConfig, get_setting, put_setting

EVENTS = {
    "weakened": "Protection was weakened",
    "new_high": "New high-severity findings",
    "run_failed": "A collection failed",
    "expiring": "A certificate or secret is about to expire",
}
SECURITY = {"starttls": "STARTTLS (port 587)", "tls": "TLS (port 465)", "none": "None (port 25)"}
DEFAULT = {"events": list(EVENTS), "webhook": None, "smtp": {}, "smtp_password": None, "base_url": ""}
REMIND = timedelta(days=7)  # how often the same expiry is repeated
MAX_ITEMS = 10
TIMEOUT = 10


def config(s: Session) -> dict:
    return {**DEFAULT, **get_setting(s, "alerts")}


def channels(cfg: dict) -> list[str]:
    return [c for c, on in (("webhook", cfg["webhook"]), ("email", cfg["smtp"].get("host"))) if on]


def gather(s: Session, job: Job, tls_cert: Path | None = None) -> list[dict]:
    """What this run gives to tell: [{"event", "title", "items"}], only for the events switched on."""
    cfg, out = config(s), []

    def add(event: str, title: str, items: list[str]) -> None:
        if items and event in cfg["events"]:
            more = [f"and {len(items) - MAX_ITEMS} more"] if len(items) > MAX_ITEMS else []
            out.append({"event": event, "title": title, "items": items[:MAX_ITEMS] + more})

    if job.status == "error":
        sc = s.query(SourceConfig).filter_by(name=job.source).one_or_none()
        if sc is None or "retry_at" not in sc.settings:  # a run that will be retried is not a failure yet
            add("run_failed", f"Collection of {job.source} failed", [job.summary or "No reason recorded"])
    elif job.started:
        weak = s.query(Change).filter(Change.source == job.source, Change.weakened, Change.time >= job.started).order_by(Change.id)
        add("weakened", f"Protection was weakened on {job.source}", [f"{c.what} {c.subject}: {c.detail or c.kind}" for c in weak])
        new = s.query(FindingState).filter(FindingState.severity == "high", FindingState.status == "open",
                                           FindingState.first_seen >= job.started).order_by(FindingState.subject)
        add("new_high", "New high-severity findings", [f"{st.title}: {st.subject}" for st in new])

    if "expiring" in cfg["events"]:
        due = [m for m, _ in sources.problems(s, tls_cert) if "last run failed" not in m]
        sent = get_setting(s, "alerts_sent")
        add("expiring", "Expiring soon", [m for m in due if m not in sent or date.fromisoformat(sent[m]) <= date.today() - REMIND])
    return out


def remember(s: Session, events: list[dict]) -> None:
    """Note the expiry warnings just delivered, so each is repeated only every REMIND; older notes are dropped."""
    today = date.today()
    sent = {m: d for m, d in get_setting(s, "alerts_sent").items() if date.fromisoformat(d) > today - REMIND}
    put_setting(s, "alerts_sent", {**sent, **{m: today.isoformat() for e in events if e["event"] == "expiring" for m in e["items"]}})
    s.commit()


def render(events: list[dict], base_url: str = "") -> tuple[str, str]:
    subject = f"WAF Inventory: {events[0]['title']}" + (f" (+{len(events) - 1} more)" if len(events) > 1 else "")
    lines = []
    for e in events:
        lines += [e["title"], *(f"  - {i}" for i in e["items"]), ""]
    if base_url:
        lines.append(f"Open the console: {base_url.rstrip('/')}/")
    return subject, "\n".join(lines).strip()


def send(cfg: dict, events: list[dict]) -> list[tuple[str, str | None]]:
    """Deliver to every configured channel: [(channel, error or None)]. One channel failing does not stop the other."""
    subject, text = render(events, cfg.get("base_url", ""))
    out = []
    for channel in channels(cfg):
        try:
            if channel == "webhook":
                httpx.post(vault.unseal(cfg["webhook"]), timeout=TIMEOUT, json={
                    "text": f"{subject}\n{text}", "title": subject, "source": "waf-inventory", "events": events}).raise_for_status()
            else:
                _email(cfg, subject, text)
            out.append((channel, None))
        except httpx.HTTPStatusError as e:  # never the URL: it is a secret
            out.append((channel, f"the webhook answered {e.response.status_code}"))
        except httpx.HTTPError as e:
            out.append((channel, f"the webhook could not be reached ({type(e).__name__})"))
        except (OSError, smtplib.SMTPException, vault.VaultError) as e:
            out.append((channel, f"{type(e).__name__}: {e}"))
    return out


def _email(cfg: dict, subject: str, text: str) -> None:
    smtp = cfg["smtp"]
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, smtp["sender"], ", ".join(smtp["to"])
    msg.set_content(text)
    tls = ssl.create_default_context()
    if smtp["security"] == "tls":
        server = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=TIMEOUT, context=tls)
    else:
        server = smtplib.SMTP(smtp["host"], smtp["port"], timeout=TIMEOUT)
    with server:
        if smtp["security"] == "starttls":
            server.starttls(context=tls)
        if smtp.get("username"):
            server.login(smtp["username"], vault.unseal(cfg["smtp_password"]) if cfg["smtp_password"] else "")
        server.send_message(msg)


def after_run(s: Session, job: Job, log: Callable[[str], None], tls_cert: Path | None = None) -> None:
    """Called when a job ends. An alert that cannot be sent is written to the job log and never fails the job."""
    try:
        cfg = config(s)
        if not channels(cfg):
            return
        events = gather(s, job, tls_cert)
        results = send(cfg, events) if events else []
        if any(error is None for _, error in results):
            remember(s, events)
        for channel, error in results:
            log(f"Alert not sent by {channel}: {error}" if error else f"Alert sent by {channel}: {', '.join(e['title'] for e in events)}")
    except Exception as e:  # alerting must not break collection
        s.rollback()
        log(f"Alert not sent: {type(e).__name__}: {e}")
