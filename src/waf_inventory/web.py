"""Dashboard: server-rendered pages over the inventory, with CSV / JSON / Excel / HTML / OpenAPI exports."""
from __future__ import annotations

import json
import re

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from . import report
from .models import Endpoint, Listener, WafPolicy, connect

PAGES = {  # table -> (title, filter columns)
    "applications": ("Applications", ["application", "gateway", "vendor", "mode"]),
    "routes": ("Routes", ["hostnames", "paths", "gateway", "waf_policy"]),
    "policies": ("WAF policies", ["policy", "vendor", "mode"]),
    "policy_settings": ("Policy settings", ["policy", "setting", "value"]),
    "endpoints": ("API endpoints", ["host", "method", "template", "kind", "mode"]),
    "findings": ("Findings", ["severity", "rule", "subject"]),
    "sources": ("Sources", ["source", "status"]),
}
MEDIA = {"csv": "text/csv", "json": "application/json",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def create_app(db: str) -> FastAPI:
    app = FastAPI(title="WAF Inventory", docs_url=None, redoc_url=None)
    engine = connect(db).get_bind()
    env = report.env

    def session() -> Session:
        return Session(engine)

    def page(template: str, **ctx) -> HTMLResponse:
        return HTMLResponse(env.get_template(template).render(pages=PAGES, **ctx))

    @app.get("/", response_class=HTMLResponse)
    def overview():
        with session() as s:
            return page("overview.html", active="", summary=report.summary(s),
                        top=report.table(s, "findings")[:10], sources=report.table(s, "sources"))

    @app.get("/t/{name}", response_class=HTMLResponse)
    def table_page(name: str, request: Request):
        if name not in PAGES:
            raise HTTPException(404)
        filters = {k: v for k, v in request.query_params.items() if k in PAGES[name][1]}
        with session() as s:
            rows = report.table(s, name, **filters)
        return page("table.html", active=name, name=name, title=PAGES[name][0], rows=rows,
                    filters=filters, filter_cols=PAGES[name][1], query=str(request.query_params))

    @app.get("/apps/{host}", response_class=HTMLResponse)
    def app_detail(host: str):
        with session() as s:
            inv = report.Inventory(s)
            listeners = inv.listeners_for(host) or [l for l in s.query(Listener) if f"{l.address or '*'}:{l.port or '*'}" == host]
            if not listeners:
                raise HTTPException(404)
            eps = s.query(Endpoint).filter_by(host=host).order_by(Endpoint.template).all()
            pols = {f"{p.vendor}: {p.name}" for l in listeners for p in [l.policy, *(r.policy for r in l.routes)] if p}
            found = [f for f in report.table(s, "findings") if host in f["subject"] or f["subject"] in pols]
            return page("app.html", active="applications", host=host, listeners=listeners, endpoints=eps, findings=found)

    @app.get("/policy/{pid}", response_class=HTMLResponse)
    def policy_detail(pid: int):
        with session() as s:
            p = s.get(WafPolicy, pid)
            if p is None:
                raise HTTPException(404)
            used = [l for l in s.query(Listener) if l.policy_id == pid or any(r.policy_id == pid for r in l.routes)]
            return page("policy.html", active="policies", p=p, used=used,
                        raw=json.dumps(p.raw, indent=2, sort_keys=True)[:200_000])

    @app.get("/export/report.html", response_class=HTMLResponse)
    def export_report():
        with session() as s:
            return HTMLResponse(report.to_html(s), headers={"Content-Disposition": 'attachment; filename="waf-inventory.html"'})

    @app.get("/export/inventory.xlsx")
    def export_all():
        with session() as s:
            return Response(report.to_xlsx(report.all_sheets(s)), media_type=MEDIA["xlsx"],
                            headers={"Content-Disposition": 'attachment; filename="waf-inventory.xlsx"'})

    @app.get("/export/openapi/{host}.json")
    def export_openapi(host: str):
        with session() as s:
            safe = re.sub(r"[^A-Za-z0-9.-]", "_", host)
            return JSONResponse(report.openapi_for(s, host),
                                headers={"Content-Disposition": f'attachment; filename="{safe}.openapi.json"'})

    @app.get("/export/{name}.{fmt}")
    def export_table(name: str, fmt: str, request: Request):
        if name not in PAGES or fmt not in MEDIA:
            raise HTTPException(404)
        filters = {k: v for k, v in request.query_params.items() if k in PAGES[name][1]}
        with session() as s:
            rows = report.table(s, name, **filters)
        body = {"csv": report.to_csv, "json": report.to_json}.get(fmt, lambda r: report.to_xlsx({name: r}))(rows)
        return Response(body, media_type=MEDIA[fmt], headers={"Content-Disposition": f'attachment; filename="{name}.{fmt}"'})

    return app
