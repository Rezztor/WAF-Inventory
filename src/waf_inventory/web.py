"""Dashboard: server-rendered pages over the inventory, with CSV / JSON / Excel / HTML / OpenAPI exports."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from . import auth, report
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
PUBLIC = {"/login", "/healthz"}
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}
MEDIA = {"csv": "text/csv", "json": "application/json",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def create_app(db: str) -> FastAPI:
    app = FastAPI(title="WAF Inventory", docs_url=None, redoc_url=None)
    engine = connect(db).get_bind()
    env = report.env

    def session() -> Session:
        return Session(engine)

    def page(request: Request, template: str, status_code: int = 200, **ctx) -> HTMLResponse:
        return HTMLResponse(env.get_template(template).render(pages=PAGES, user=request.state.user, csrf=request.state.csrf, **ctx),
                            status_code=status_code)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD") and origin and urlsplit(origin).netloc != request.headers.get("host"):
            return PlainTextResponse("Cross-origin request refused", 403)
        with session() as s:
            ls = auth.load_session(s, request.cookies.get(auth.COOKIE))
            request.state.user, request.state.csrf = (ls.user.username, ls.csrf) if ls else (None, None)
        if ls is None and request.url.path not in PUBLIC:
            if request.method != "GET":
                return PlainTextResponse("Sign in first", 401)
            target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/login?next={quote(target)}", 303)
        response = await call_next(request)
        response.headers.update(HEADERS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    async def form(request: Request) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True).items()}

    def safe_next(target: str | None) -> str:
        return target if target and target.startswith("/") and not target.startswith("//") and "\\" not in target else "/"

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = "/"):
        if request.state.user:
            return RedirectResponse(safe_next(next), 303)
        return page(request, "login.html", next=safe_next(next))

    @app.post("/login")
    async def login(request: Request):
        f = await form(request)
        username, password, nxt = f.get("username", "").strip(), f.get("password", ""), safe_next(f.get("next"))
        ip = request.client.host if request.client else None
        keys = (f"user:{username.lower()}", f"ip:{ip}")
        if wait := auth.wait_seconds(*keys):
            return page(request, "login.html", 429, next=nxt, username=username,
                        error=f"Too many failed sign-ins. Try again in {(wait + 59) // 60} minute(s).")
        with session() as s:
            user = auth.authenticate(s, username, password)
            auth.record_attempt(user is not None, *keys)
            if user is None:
                return page(request, "login.html", 401, next=nxt, username=username, error="Wrong username or password.")
            token = auth.start_session(s, user, ip, request.headers.get("user-agent"))
        r = RedirectResponse(nxt, 303)
        r.set_cookie(auth.COOKIE, token, httponly=True, secure=request.url.scheme == "https", samesite="strict")
        return r

    @app.post("/logout")
    async def logout(request: Request):
        if (await form(request)).get("csrf") != request.state.csrf:
            raise HTTPException(403, "Invalid form token; reload the page and try again")
        with session() as s:
            auth.end_session(s, request.cookies.get(auth.COOKIE))
        r = RedirectResponse("/login", 303)
        r.delete_cookie(auth.COOKIE)
        return r

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        with session() as s:
            return page(request, "overview.html", active="", summary=report.summary(s),
                        top=report.table(s, "findings")[:10], sources=report.table(s, "sources"))

    @app.get("/t/{name}", response_class=HTMLResponse)
    def table_page(name: str, request: Request):
        if name not in PAGES:
            raise HTTPException(404)
        filters = {k: v for k, v in request.query_params.items() if k in PAGES[name][1]}
        with session() as s:
            rows = report.table(s, name, **filters)
        return page(request, "table.html", active=name, name=name, title=PAGES[name][0], rows=rows,
                    filters=filters, filter_cols=PAGES[name][1], query=str(request.query_params))

    @app.get("/apps/{host}", response_class=HTMLResponse)
    def app_detail(host: str, request: Request):
        with session() as s:
            inv = report.Inventory(s)
            listeners = inv.listeners_for(host) or [l for l in s.query(Listener) if f"{l.address or '*'}:{l.port or '*'}" == host]
            if not listeners:
                raise HTTPException(404)
            eps = s.query(Endpoint).filter_by(host=host).order_by(Endpoint.template).all()
            pols = {f"{p.vendor}: {p.name}" for l in listeners for p in [l.policy, *(r.policy for r in l.routes)] if p}
            found = [f for f in report.table(s, "findings") if host in f["subject"] or f["subject"] in pols]
            return page(request, "app.html", active="applications", host=host, listeners=listeners, endpoints=eps, findings=found)

    @app.get("/policy/{pid}", response_class=HTMLResponse)
    def policy_detail(pid: int, request: Request):
        with session() as s:
            p = s.get(WafPolicy, pid)
            if p is None:
                raise HTTPException(404)
            used = [l for l in s.query(Listener) if l.policy_id == pid or any(r.policy_id == pid for r in l.routes)]
            return page(request, "policy.html", active="policies", p=p, used=used,
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
