"""Inventory views (one list of row dicts per table) and exports: CSV, JSON, Excel, HTML report, OpenAPI."""
from __future__ import annotations

import csv
import io
import json
from fnmatch import fnmatchcase as fnmatch

from jinja2 import Environment, PackageLoader, select_autoescape
from openpyxl import Workbook
from sqlalchemy.orm import Session

from . import tuning as _tuning_mod
from .discovery import openapi
from .models import Change, Endpoint, Finding, Gateway, Listener, Source, WafPolicy

TABLES = ("applications", "routes", "policies", "policy_settings", "endpoints", "findings", "tuning", "changes", "sources")
env = Environment(loader=PackageLoader("waf_inventory"), autoescape=select_autoescape())


# ---------------------------------------------------------------- effective policy

class Inventory:
    """Listeners indexed by hostname, to answer "which WAF policy protects host + path?"."""

    def __init__(self, session: Session):
        self.listeners = session.query(Listener).join(Gateway).all()
        self.exact: dict[str, list[Listener]] = {}
        self.wild: list[tuple[str, Listener]] = []
        for lst in self.listeners:
            for h in lst.hostnames:
                if "*" in h:
                    self.wild.append((h, lst))
                else:
                    self.exact.setdefault(h, []).append(lst)

    def listeners_for(self, host: str) -> list[Listener]:
        return self.exact.get(host) or [lst for pat, lst in self.wild if fnmatch(host, pat)]

    def effective(self, host: str, path: str) -> tuple[Listener | None, WafPolicy | None]:
        """First matching route in evaluation order (routes are stored in that order, catch-all last)."""
        first = None
        for lst in self.listeners_for(host):
            if not lst.waf_capable:
                continue
            first = first or lst
            for r in lst.routes:
                if (not r.hosts or any(fnmatch(host, h) for h in r.hosts)) and any(fnmatch(path, p) for p in r.paths or ["/*"]):
                    return lst, r.policy
        return first, first.policy if first else None


# ---------------------------------------------------------------- tables

def _settings_summary(p: WafPolicy | None) -> str:
    if p is None:
        return ""
    return ", ".join(f"{r.get('type')} {r.get('version')}" for r in p.settings.get("rulesets", [])) or p.settings.get("template") or ""


def table(session: Session, name: str, **filters) -> list[dict]:
    if name not in TABLES:
        raise KeyError(name)
    rows = globals()[f"_{name}"](session)
    for k, v in filters.items():
        if v not in (None, ""):
            rows = [r for r in rows if str(v).lower() in str(r.get(k, "")).lower()]
    return rows


def _applications(s: Session) -> list[dict]:
    hits: dict[str, int] = {}
    for e in s.query(Endpoint):
        hits[e.host] = hits.get(e.host, 0) + e.hits
    rows = []
    for lst in s.query(Listener).join(Gateway).order_by(Gateway.name, Listener.name):
        g = lst.gateway
        for host in lst.hostnames or [f"{lst.address or '*'}:{lst.port or '*'}"]:
            protected = sum(1 for r in lst.routes if r.policy)
            rows.append({
                "application": host, "gateway": g.name, "vendor": g.vendor, "type": g.kind, "listener": lst.name,
                "protocol": lst.protocol, "port": lst.port, "waf_capable": lst.waf_capable,
                "waf_policy": lst.policy.name if lst.policy else "", "mode": lst.policy.mode if lst.policy else "none",
                "ruleset": _settings_summary(lst.policy), "routes": len(lst.routes), "routes_protected": protected,
                "requests_seen": hits.get(host, 0), "source": g.source.name})
    return rows


def _routes(s: Session) -> list[dict]:
    rows = []
    for lst in s.query(Listener).join(Gateway).order_by(Gateway.name, Listener.name):
        for r in lst.routes:
            b = r.backend or {}
            rows.append({"gateway": lst.gateway.name, "listener": lst.name, "hostnames": ", ".join(r.hosts or lst.hostnames),
                         "route": r.name, "paths": ", ".join(r.paths), "backend": b.get("name") or "",
                         "backend_members": ", ".join(m for m in b.get("members", []) if m),
                         "waf_policy": r.policy.name if r.policy else "", "mode": r.policy.mode if r.policy else "none"})
    return rows


def _policies(s: Session) -> list[dict]:
    used: dict[int, set] = {}
    for lst in s.query(Listener):
        for pid in {lst.policy_id, *(r.policy_id for r in lst.routes)} - {None}:
            used.setdefault(pid, set()).add(lst.name)
    rows = []
    for p in s.query(WafPolicy).order_by(WafPolicy.vendor, WafPolicy.name):
        st = p.settings
        rows.append({"id": p.id, "source": p.source.name, "vendor": p.vendor, "policy": p.name, "mode": p.mode,
                     "rulesets": _settings_summary(p), "bot": st.get("bot", ""),
                     "disabled_rules": len(st.get("disabled_rules", [])), "exclusions": len(st.get("exclusions", [])),
                     "custom_rules": len(st.get("custom_rules", [])), "rate_limits": len(st.get("rate_limits", [])),
                     "allowed_urls": len(st.get("allowed_urls", [])), "attached_to": len(used.get(p.id, ())),
                     "raw_hash": p.raw_hash[:12]})
    return rows


def _policy_settings(s: Session) -> list[dict]:
    rows = []
    for p in s.query(WafPolicy).order_by(WafPolicy.vendor, WafPolicy.name):
        for key, value in p.settings.items():
            items = value if isinstance(value, list) else [value]
            for v in items:
                rows.append({"policy": p.name, "vendor": p.vendor, "setting": key,
                             "value": json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v})
    return rows


def _endpoints(s: Session) -> list[dict]:
    inv = Inventory(s)
    rows = []
    for e in s.query(Endpoint).order_by(Endpoint.host, Endpoint.template, Endpoint.method):
        lst, pol = inv.effective(e.host, e.samples[0] if e.samples else e.template)
        rows.append({"host": e.host, "method": e.method, "template": e.template, "kind": e.kind,
                     "confidence": e.confidence, "confirmed": e.confirmed, "hits": e.hits,
                     "first_seen": e.first_seen, "last_seen": e.last_seen,
                     "statuses": ", ".join(f"{k}×{v}" for k, v in sorted(e.statuses.items())),
                     "query_params": ", ".join(e.query_params), "content_types": ", ".join(e.content_types),
                     "gateway": lst.gateway.name if lst else "", "waf_policy": pol.name if pol else "",
                     "mode": pol.mode if pol else "none"})
    return rows


def _findings(s: Session) -> list[dict]:
    order = {"high": 0, "medium": 1, "low": 2}
    rows = [{"severity": f.severity, "rule": f.rule, "title": f.title, "subject": f.subject, "detail": f.detail}
            for f in s.query(Finding)]
    return sorted(rows, key=lambda r: (order.get(r["severity"], 9), r["rule"], r["subject"]))


def _changes(s: Session) -> list[dict]:
    return [{"time": c.time.strftime("%Y-%m-%d %H:%M"), "source": c.source, "change": c.kind, "what": c.what, "subject": c.subject,
             "detail": c.detail, "weakened": "yes" if c.weakened else ""}
            for c in s.query(Change).order_by(Change.time.desc(), Change.weakened.desc(), Change.id)]


def _sources(s: Session) -> list[dict]:
    return [{"source": x.name, "kind": x.kind, "status": x.status, "last_run": x.last_run, "error": x.error or "",
             "gateways": len(x.gateways), "policies": len(x.policies), "endpoints": len(x.endpoints)}
            for x in s.query(Source).order_by(Source.name)]


def _tuning(s: Session) -> list[dict]:
    return [{"verdict": g["verdict"], "score": g["score"], "proxy": g["proxy"], "host": g["host"], "method": g["method"],
             "path": g["path"], "rule": g["rule"], "rule_name": g["rule_name"], "events": g["events"], "sources": g["sources"],
             "days": g["days"], "first": g["first"], "last": g["last"], "evidence": "; ".join(g["evidence"] + g["attack_signs"]),
             "proposal": f"exclude {g['proposal']['rule']} on {g['proposal']['match']}" if g["proposal"] else g["note"],
             "decision": g["decision"]} for g in _tuning_mod.groups(s)]


def summary(s: Session) -> dict:
    apps = table(s, "applications")
    web = [a for a in apps if a["waf_capable"]]
    findings = table(s, "findings")
    return {
        "applications": len({a["application"] for a in apps}),
        "vendors": sorted({v for (v,) in s.query(Gateway.vendor).distinct()}),
        "gateways": s.query(Gateway).count(), "policies": s.query(WafPolicy).count(),
        "endpoints": s.query(Endpoint).count(), "api_endpoints": s.query(Endpoint).filter_by(kind="api").count(),
        "coverage": round(100 * sum(a["mode"] == "block" for a in web) / len(web)) if web else 0,
        "modes": {m: sum(a["mode"] == m for a in web) for m in ("block", "detect", "off", "unknown", "none")},
        "findings": {sev: sum(f["severity"] == sev for f in findings) for sev in ("high", "medium", "low")},
    }


# ---------------------------------------------------------------- exports

def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows({k: _cell(v) for k, v in r.items()} for r in rows)
    return buf.getvalue()


def to_json(rows) -> str:
    return json.dumps(rows, indent=2, default=str)


def to_xlsx(sheets: dict[str, list[dict]]) -> bytes:
    wb = Workbook()
    wb.remove(wb.active)
    for name, rows in sheets.items():
        ws = wb.create_sheet(name[:31])
        if not rows:
            continue
        cols = list(rows[0])
        ws.append(cols)
        for r in rows:
            ws.append([_cell(r.get(c)) for c in cols])
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _cell(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):  # no formula injection from log/config data
        return "'" + v
    return v if isinstance(v, (int, float, bool, str)) or v is None else str(v)


def to_html(session: Session) -> str:
    """Self-contained full-inventory report."""
    sheets = {n: table(session, n) for n in TABLES}
    return env.get_template("report.html").render(summary=summary(session), sheets=sheets)


def all_sheets(session: Session) -> dict[str, list[dict]]:
    return {n: table(session, n) for n in TABLES}


def openapi_for(session: Session, host: str) -> dict:
    return openapi(host, session.query(Endpoint).filter_by(host=host).all())
