"""Dashboard: server-rendered pages over the inventory, with CSV / JSON / Excel / HTML / OpenAPI exports."""
from __future__ import annotations

import base64
import hmac
import json
import re
import tomllib
from datetime import date, timedelta
from importlib import metadata
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from . import auth, f5, findings, jobs, remedies, report, sources, tls, tuning, vault
from .models import (AuditLog, Endpoint, Finding, Job, Listener, Source, SourceConfig, TuningDecision, WafPolicy, connect, get_setting,
                     put_setting)

PAGES = {  # table -> (title, filter columns)
    "applications": ("Applications", ["application", "gateway", "vendor", "mode"]),
    "routes": ("Routes", ["hostnames", "paths", "gateway", "waf_policy"]),
    "policies": ("WAF policies", ["policy", "vendor", "mode"]),
    "policy_settings": ("Policy settings", ["policy", "setting", "value"]),
    "endpoints": ("API endpoints", ["host", "method", "template", "kind", "mode"]),
    "findings": ("Findings", ["severity", "rule", "subject"]),
    "tuning": ("Tuning", ["verdict", "proxy", "rule", "path"]),
    "changes": ("Changes", ["source", "what", "subject", "weakened"]),
    "sources": ("Sources", ["source", "status"]),
}
PUBLIC = {"/login", "/healthz"}
FONTS = Path(__file__).parent / "static" / "fonts"
VERSION = metadata.version("waf-inventory")
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}
MESSAGES = {
    "created": "Source saved. Next: Test connection.",
    "saved": "Saved.",
    "deleted": "Source deleted, together with its inventory data.",
    "trusted": "Certificate trusted. Test connection to confirm it works.",
    "certificate": "New certificate made. Download the .cer and upload it to the app registration, then Test connection.",
    "rotating": "Second certificate made. Upload its .cer to the app registration, then Test the new certificate.",
    "scope": "Scope saved. Run now to collect it.",
    "general": "Settings saved. They apply from the next run.",
    "installed": "Certificate installed. New connections use it now; reload the page to see it in your browser.",
    "imported": "Import finished.",
    "collection": "Saved. Connections on the default schedule now follow it.",
    "uploaded": "Files uploaded. A collection has started: see Jobs.",
    "key-trusted": "Host key trusted. Test connection to confirm the sign-in works.",
}
AZURE_SIGN_IN = {"certificate": "App registration · certificate", "secret": "App registration · client secret",
                 "managed_identity": "Managed identity", "default": "This machine's Azure login"}
MEDIA = {"csv": "text/csv", "json": "application/json",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def create_app(db: str, cfg: dict | None = None, tls_dir: str | None = None, background: bool = False) -> FastAPI:
    """`background` starts the scheduler (the server does; tests drive jobs.tick themselves).
    `app.state.reload_tls`, set by the server, loads a newly installed HTTPS certificate without a restart."""
    app = FastAPI(title="WAF Inventory", docs_url=None, redoc_url=None)
    engine = connect(db).get_bind()
    env = report.env
    cfg = cfg or {"_dir": Path.cwd()}
    tls_path = Path(tls_dir) if tls_dir else None
    jobs.interrupted(engine)
    runner = jobs.Runner(engine, cfg)
    app.state.reload_tls = None
    if background:
        jobs.start_scheduler(engine, runner)

    def session() -> Session:
        return Session(engine)

    def audit(s: Session, request: Request, action: str, target: str = "", user: str | None = None, **detail) -> None:
        """Record an action; the caller commits. Never pass a secret value in `detail`."""
        s.add(AuditLog(time=auth._now(), user=user or request.state.user, ip=request.client.host if request.client else None,
                       action=action, target=target, detail=detail))

    def page(request: Request, template: str, status_code: int = 200, **ctx) -> HTMLResponse:
        nav = None
        if request.state.user:  # the side menu's findings count and collector line
            with session() as s:
                nxt = min((x.settings["next_run"] for x in s.query(SourceConfig) if x.settings.get("next_run")), default=None)
                nav = {"high": s.query(Finding).filter_by(severity="high").count(), "next": nxt, "version": VERSION,
                       "running": s.query(Job).filter(Job.status == "running").count()}
        return HTMLResponse(env.get_template(template).render(pages=PAGES, user=request.state.user, csrf=request.state.csrf, nav=nav,
                                                              **ctx), status_code=status_code)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD") and origin and urlsplit(origin).netloc != request.headers.get("host"):
            return PlainTextResponse("Cross-origin request refused", 403)
        with session() as s:
            ls = auth.load_session(s, request.cookies.get(auth.COOKIE))
            request.state.user, request.state.csrf = (ls.user.username, ls.csrf) if ls else (None, None)
        if ls is None and request.url.path not in PUBLIC and not request.url.path.startswith("/fonts/"):
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

    async def checked_form(request: Request) -> dict[str, str]:
        """Form fields of a signed-in POST, after checking its CSRF token. Uploaded files land in request.state.files."""
        request.state.files = []
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            fd = await request.form()
            f = {k: v for k, v in fd.items() if isinstance(v, str)}
            request.state.files = [x for x in fd.getlist("files") if not isinstance(x, str) and x.filename]
        else:
            f = await form(request)
        if not request.state.csrf or not hmac.compare_digest(f.get("csrf", ""), request.state.csrf):
            raise HTTPException(403, "Invalid form token; reload the page and try again")
        return f

    def safe_next(target: str | None) -> str:
        return target if target and target.startswith("/") and not target.startswith("//") and "\\" not in target else "/"

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/fonts/{name}")
    def font(name: str):
        f = FONTS / name
        if f.parent != FONTS or not f.is_file():
            raise HTTPException(404)
        return FileResponse(f, headers={"Cache-Control": "public, max-age=31536000, immutable"})

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = "/", changed: str = ""):
        if request.state.user:
            return RedirectResponse(safe_next(next), 303)
        return page(request, "login.html", next=safe_next(next), notice="Password changed. Sign in with the new one." if changed else None)

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
                audit(s, request, "sign-in failed", username[:100])
                s.commit()
                return page(request, "login.html", 401, next=nxt, username=username, error="Wrong username or password.")
            audit(s, request, "signed in", user=user.username)
            token = auth.start_session(s, user, ip, request.headers.get("user-agent"))
        r = RedirectResponse(nxt, 303)
        r.set_cookie(auth.COOKIE, token, httponly=True, secure=request.url.scheme == "https", samesite="strict")
        return r

    @app.post("/logout")
    async def logout(request: Request):
        await checked_form(request)
        with session() as s:
            audit(s, request, "signed out")
            auth.end_session(s, request.cookies.get(auth.COOKIE))
        r = RedirectResponse("/login", 303)
        r.delete_cookie(auth.COOKIE)
        return r

    # ------------------------------------------------------------ sources and jobs

    def source_page(request: Request, s: Session, sc: SourceConfig, status_code: int = 200, **ctx) -> HTMLResponse:
        recent = [] if sc.id is None else s.query(Job).filter_by(source=sc.name).order_by(Job.id.desc()).limit(5).all()
        default = sources.collection(s)
        return page(request, "source.html", status_code, active="console_sources", sc=sc, new=sc.id is None,
                    title=sources.TYPES[sc.type][0], fields={f.key: f for f in sources.TYPES[sc.type][1]},
                    secrets=sources.secret_state(sc), recent=recent, days=sources.DAYS, zones=sources.ZONES, default=default,
                    default_text=sources.describe({"every": "default"}, default), sched=sc.settings.get("schedule") or {}, **ctx)

    def connection(sc: SourceConfig | None, inv: Source | None, job: Job | None, default: dict) -> dict:
        """One row of Settings › Connections and of the overview: how it signs in, its schedule and its state."""
        st, secrets = (sc.settings, sources.secret_state(sc)) if sc else ({}, {})
        kind = sc.type if sc else inv.kind
        soon, note, warn = date.today() + timedelta(days=sources.WARN_DAYS), "", None
        if kind == "azure":
            method = AZURE_SIGN_IN.get(st.get("auth"), "")
            if st.get("auth") == "certificate" and (c := secrets.get("certificate")):
                note = f"Certificate valid until {c['meta']['expires']}"
                warn = sources.day(c["meta"]["expires"]) and sources.day(c["meta"]["expires"]) <= soon and "Certificate expires soon"
            elif st.get("auth") == "secret" and st.get("client_secret_expires"):
                note = f"Secret expires {st['client_secret_expires']}"
                warn = (d := sources.day(st["client_secret_expires"])) and d <= soon and "Secret expires soon"
            else:
                note = dict(sources.AZURE_CLOUDS).get(st.get("cloud", "public"), "")
        elif kind == "f5_rest":
            method = "REST API · " + ("token sign-in" if st.get("token", True) else "basic sign-in")
            note = "Device certificate pinned" if st.get("ca_fingerprint") else "Device certificate not pinned"
        elif kind == "f5_ssh":
            method = "SSH · " + ("key" if st.get("ssh_auth") == "key" else "password")
            note = "Host key pinned · read-only tmsh" if st.get("host_key") else "Host key not trusted yet"
        elif kind == "baffinbay":
            method, note = "Service account", f"Tenant {st.get('tenant_id', '')}"
        else:
            method = {"f5_offline": "Offline files", "azure_bundle": "Offline bundle file", "baffinbay_bundle": "Offline bundle file",
                      "logs": "Access-log files"}.get(kind, kind)
            note = st.get("path", "")
        if job:
            tone, status = "neu", job.status.capitalize()
        elif inv is None or inv.status == "never run":
            tone, status = "neu", "Never run"
        elif inv.status == "error":
            tone, status = "crit", "Failed"
        elif warn:
            tone, status = "warn", warn
        else:
            tone, status = "ok", "Working"
        return {"sc": sc, "inv": inv, "job": job, "name": sc.name if sc else inv.name, "badge": "AZ" if kind.startswith("azure") else
                "LOG" if kind == "logs" else "BB" if kind.startswith("baffinbay") else "F5", "title": sources.TYPES[kind][0] if kind in sources.TYPES else kind,
                "method": method, "note": note, "tone": tone, "status": status,
                "schedule": sources.describe(st.get("schedule"), default) if sc else "Config file",
                "next": st.get("next_run")}

    def connections(s: Session) -> list[dict]:
        default = sources.collection(s)
        inv = {x.name: x for x in s.query(Source)}
        active = {j.source: j for j in s.query(Job).filter(Job.status.in_(jobs.ACTIVE))}
        rows = [connection(sc, inv.pop(sc.name, None), active.get(sc.name), default)
                for sc in s.query(SourceConfig).order_by(SourceConfig.name)]
        return rows + [connection(None, x, active.get(x.name), default) for x in inv.values()]  # collected from config.toml by the CLI

    def get_source(s: Session, sid: int) -> SourceConfig:
        sc = s.get(SourceConfig, sid)
        if sc is None:
            raise HTTPException(404)
        return sc

    @app.get("/sources", response_class=HTMLResponse)
    def sources_list(request: Request, msg: str = ""):
        with session() as s:
            rows = [r for r in connections(s) if r["sc"]]
            return page(request, "sources.html", active="settings", tab="connections", rows=rows, msg=MESSAGES.get(msg),
                        problems=sources.problems(s, tls_cert()))

    @app.get("/sources/new/{kind}", response_class=HTMLResponse)
    def source_new(kind: str, request: Request):
        if kind not in sources.TYPES:
            raise HTTPException(404)
        with session() as s:
            return source_page(request, s, SourceConfig(type=kind, name="", settings=dict(sources.DEFAULTS.get(kind, {}))))

    @app.post("/sources/new/{kind}")
    async def source_create(kind: str, request: Request):
        if kind not in sources.TYPES:
            raise HTTPException(404)
        f = await checked_form(request)
        files = request.state.files
        with session() as s:
            sc = SourceConfig(type=kind, name=f.get("name", "").strip(), settings=dict(sources.DEFAULTS.get(kind, {})))
            try:
                errors = ([] if sc.name else ["Name is required"]) + sources.apply_form(sc, f, sources.collection(s))
                if sc.name and s.query(SourceConfig).filter_by(name=sc.name).first():
                    errors.append("A source with that name already exists")
                if kind == "f5_offline" and not files and not sc.settings.get("path"):
                    errors.append("Upload the device's files, or enter a folder on the server")
                if not errors and kind == "azure" and sc.settings.get("auth") == "certificate":
                    sources.make_azure_certificate(sc)
            except vault.VaultError as e:
                errors = [str(e)]
            if errors:
                return source_page(request, s, sc, 422, errors=errors)
            s.add(sc)
            s.flush()
            if files and (errors := sources.save_uploads(sc, files, uploads(sc))):
                s.rollback()
                return source_page(request, s, sc, 422, errors=errors)
            audit(s, request, "source added", sc.name, type=kind, secrets=sorted(sources.secret_state(sc)),
                  **({"files": [x.filename for x in files]} if files else {}))
            s.commit()
            return await then(request, s, sc, f.get("then"), "created")

    def uploads(sc: SourceConfig) -> Path:
        return cfg["_dir"] / "uploads" / str(sc.id)

    async def then(request: Request, s: Session, sc: SourceConfig, step: str | None, msg: str):
        """After a save: the step the button asked for (Save and test, Fetch certificate, Fetch host key), else back to the page."""
        if step == "test":
            return await test_page(request, sc.id, "certificate")
        if step == "fetch-cert" and sc.type == "f5_rest":
            return await fetch_cert_page(request, sc.id)
        if step == "fetch-key" and sc.type == "f5_ssh":
            return await fetch_key_page(request, sc.id)
        return RedirectResponse(f"/sources/{sc.id}?msg={msg}", 303)

    @app.get("/sources/{sid}", response_class=HTMLResponse)
    def source_edit(sid: int, request: Request, msg: str = ""):
        with session() as s:
            return source_page(request, s, get_source(s, sid), msg=MESSAGES.get(msg))

    @app.post("/sources/{sid}")
    async def source_save(sid: int, request: Request):
        f = await checked_form(request)
        files = request.state.files
        with session() as s:
            sc = get_source(s, sid)
            before = dict(sc.settings)
            try:
                errors = sources.apply_form(sc, f, sources.collection(s))
                if sc.type == "f5_offline" and files:
                    errors += sources.save_uploads(sc, files, uploads(sc))
                elif sc.type == "f5_offline" and not sc.settings.get("path"):
                    errors.append("Upload the device's files, or enter a folder on the server")
                if not errors and sc.type == "azure" and sc.settings.get("auth") == "certificate" and "certificate" not in sources.secret_state(sc):
                    sources.make_azure_certificate(sc)
            except vault.VaultError as e:
                errors = [str(e)]
            if errors:
                r = source_page(request, s, sc, 422, errors=errors)  # rendered with what was typed, then discarded
                s.rollback()
                return r
            audit(s, request, "source changed", sc.name,
                  settings=sorted(k for k in {*before, *sc.settings} if before.get(k) != sc.settings.get(k) and k != "next_run"),
                  secrets=[x.key for x in sources.TYPES[sc.type][1] if x.kind == "secret" and f.get(x.key, "").strip()],
                  **({"files": [x.filename for x in files]} if files else {}))
            s.commit()
            if files:
                runner.submit(s, sc, trigger="upload")
                return RedirectResponse(f"/sources/{sid}?msg=uploaded", 303)
            return await then(request, s, sc, f.get("then"), "saved")

    def _test(sid: int, certificate: str) -> tuple[bool, list[str], dict | None]:  # in a worker thread: it waits on the network
        with session() as s:
            sc = get_source(s, sid)
            try:
                found = sources.test(cfg, sc, certificate)
                s.commit()  # a Baffin Bay token issued during the test is kept
                return True, *found
            except Exception as e:
                return False, [sources.explain(e, sc)], None

    @app.post("/sources/{sid}/test", response_class=HTMLResponse)
    async def source_test(sid: int, request: Request):
        """Test connection. With certificate=certificate_next (rotation), a pass makes the new certificate the one in use."""
        f = await checked_form(request)
        return await test_page(request, sid, "certificate_next" if f.get("certificate") == "certificate_next" else "certificate")

    async def test_page(request: Request, sid: int, certificate: str) -> HTMLResponse:
        ok, lines, found = await run_in_threadpool(_test, sid, certificate)
        with session() as s:
            sc = get_source(s, sid)
            audit(s, request, "connection tested", sc.name, ok=ok, certificate=certificate if sc.type == "azure" else None)
            if ok and certificate == "certificate_next":
                sources.promote_next_certificate(sc)
                audit(s, request, "certificate rotated", sc.name)
                lines.append("The new certificate is now in use; the old one is deleted here. Remove it from the app registration too.")
            s.commit()
            return source_page(request, s, sc, test={"ok": ok, "lines": lines}, found=found)

    @app.post("/sources/{sid}/scope")
    async def source_scope(sid: int, request: Request):
        """Subscriptions and workspaces ticked in the picker shown after a successful Azure test."""
        body = parse_qs((await request.body()).decode())
        if not request.state.csrf or not hmac.compare_digest(body.get("csrf", [""])[0], request.state.csrf):
            raise HTTPException(403, "Invalid form token; reload the page and try again")
        with session() as s:
            sc = get_source(s, sid)
            sc.settings = {**sc.settings, "subscriptions": body.get("subscriptions", []), "log_workspaces": body.get("log_workspaces", [])}
            audit(s, request, "source changed", sc.name, settings=["subscriptions", "log_workspaces"])
            s.commit()
            return RedirectResponse(f"/sources/{sid}?msg=scope", 303)

    @app.post("/sources/{sid}/run")
    async def source_run(sid: int, request: Request):
        await checked_form(request)
        with session() as s:
            sc = get_source(s, sid)
            audit(s, request, "run started", sc.name)
            job = runner.submit(s, sc)
            return RedirectResponse(f"/jobs/{job.id}", 303)

    @app.post("/sources/{sid}/delete", response_class=HTMLResponse)
    async def source_delete(sid: int, request: Request):
        f = await checked_form(request)
        with session() as s:
            sc = get_source(s, sid)
            if not auth.authenticate(s, request.state.user, f.get("password", "")):
                return source_page(request, s, sc, 403, delete_error="Wrong password. The source was not deleted.")
            if s.query(Job).filter(Job.source == sc.name, Job.status.in_(jobs.ACTIVE)).first():
                return source_page(request, s, sc, 409, delete_error="A collection of this source is queued or running. "
                                   "Delete it once that job has finished.")
            inv = s.query(Source).filter_by(name=sc.name).one_or_none()
            for x in (sc, inv):
                if x is not None:
                    s.delete(x)
            audit(s, request, "source deleted", sc.name)
            s.commit()
            from .cli import load_specs
            findings.run(s, load_specs(cfg))
            return RedirectResponse("/sources?msg=deleted", 303)

    @app.post("/sources/{sid}/azure/certificate")
    async def azure_certificate(sid: int, request: Request):
        await checked_form(request)
        with session() as s:
            sc = get_source(s, sid)
            if sc.type != "azure":
                raise HTTPException(404)
            rotate = "certificate" in sources.secret_state(sc)  # keep the working one until the new one tests fine
            sources.make_azure_certificate(sc, "certificate_next" if rotate else "certificate")
            audit(s, request, "certificate made", sc.name, rotation=rotate)
            s.commit()
            return RedirectResponse(f"/sources/{sid}?msg={'rotating' if rotate else 'certificate'}", 303)

    @app.post("/sources/{sid}/azure/cancel-rotation")
    async def azure_cancel_rotation(sid: int, request: Request):
        await checked_form(request)
        with session() as s:
            sc = get_source(s, sid)
            sc.secrets = [x for x in sc.secrets if x.kind != "certificate_next"]
            audit(s, request, "certificate rotation cancelled", sc.name)
            s.commit()
            return RedirectResponse(f"/sources/{sid}", 303)

    @app.get("/sources/{sid}/azure/certificate.cer")
    def azure_certificate_download(sid: int, next: int = 0):
        with session() as s:
            meta = sources.secret_state(get_source(s, sid)).get("certificate_next" if next else "certificate", {}).get("meta")
            if not meta:
                raise HTTPException(404)
            der = x509.load_pem_x509_certificate(meta["cert_pem"].encode()).public_bytes(serialization.Encoding.DER)
            return Response(der, media_type="application/pkix-cert",
                            headers={"Content-Disposition": f'attachment; filename="waf-inventory-{sid}{"-new" if next else ""}.cer"'})

    @app.post("/sources/{sid}/f5/fetch-cert", response_class=HTMLResponse)
    async def f5_fetch_cert(sid: int, request: Request):
        await checked_form(request)
        return await fetch_cert_page(request, sid)

    async def fetch_cert_page(request: Request, sid: int) -> HTMLResponse:
        with session() as s:
            st = get_source(s, sid).settings
            host = f5.address(st.get("host", ""), st.get("port"))
        try:
            fetched, error = await run_in_threadpool(sources.fetch_certificate, host), None
        except Exception as e:
            fetched, error = None, sources.explain(e)
        with session() as s:
            return source_page(request, s, get_source(s, sid), fetched=fetched, errors=[error] if error else None)

    @app.post("/sources/{sid}/f5/trust-cert")
    async def f5_trust_cert(sid: int, request: Request):
        f = await checked_form(request)
        try:
            cert = x509.load_pem_x509_certificate(f.get("pem", "").encode())
        except ValueError:
            raise HTTPException(400, "Not a certificate") from None
        fp = cert.fingerprint(hashes.SHA256()).hex(":").upper()
        if fp != f.get("fingerprint"):
            raise HTTPException(400, "The certificate does not match the fingerprint shown; fetch it again")
        with session() as s:
            sc = get_source(s, sid)
            sc.settings = {**sc.settings, "ca_pem": cert.public_bytes(serialization.Encoding.PEM).decode(), "ca_fingerprint": fp,
                           "ca_subject": cert.subject.rfc4514_string(), "ca_expires": cert.not_valid_after_utc.date().isoformat()}
            audit(s, request, "device certificate trusted", sc.name, fingerprint=fp)
            s.commit()
            return RedirectResponse(f"/sources/{sid}?msg=trusted", 303)

    @app.post("/sources/{sid}/ssh/fetch-key", response_class=HTMLResponse)
    async def ssh_fetch_key(sid: int, request: Request):
        await checked_form(request)
        return await fetch_key_page(request, sid)

    async def fetch_key_page(request: Request, sid: int) -> HTMLResponse:
        with session() as s:
            st = get_source(s, sid).settings
        try:
            fetched, error = await run_in_threadpool(sources.fetch_host_key, st.get("host", ""), st.get("port", 22)), None
        except Exception as e:
            fetched, error = None, sources.explain(e)
        with session() as s:
            return source_page(request, s, get_source(s, sid), fetched_key=fetched, errors=[error] if error else None)

    @app.post("/sources/{sid}/ssh/trust-key")
    async def ssh_trust_key(sid: int, request: Request):
        f = await checked_form(request)
        kind, key = f.get("key_type", ""), f.get("key", "")
        try:
            fp = sources.ssh_fingerprint(base64.b64decode(key, validate=True))
        except ValueError:
            raise HTTPException(400, "Not a host key") from None
        if fp != f.get("fingerprint") or not re.fullmatch(r"[\w@.-]+", kind):
            raise HTTPException(400, "The host key does not match the fingerprint shown; fetch it again")
        with session() as s:
            sc = get_source(s, sid)
            sc.settings = {**sc.settings, "host_key": f"{kind} {key}", "host_key_fingerprint": fp}
            audit(s, request, "ssh host key trusted", sc.name, fingerprint=fp)
            s.commit()
            return RedirectResponse(f"/sources/{sid}?msg=key-trusted", 303)

    @app.post("/jobs/run-all")
    async def run_all(request: Request):
        await checked_form(request)
        with session() as s:
            audit(s, request, "run started", "all")
            for sc in s.query(SourceConfig).order_by(SourceConfig.name):
                runner.submit(s, sc)
            return RedirectResponse("/jobs", 303)

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs_list(request: Request):
        with session() as s:
            return page(request, "jobs.html", active="jobs", jobs=s.query(Job).order_by(Job.id.desc()).limit(200).all())

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job_detail(jid: int, request: Request):
        with session() as s:
            job = s.get(Job, jid)
            if job is None:
                raise HTTPException(404)
            sc = s.query(SourceConfig).filter_by(name=job.source).one_or_none()
            return page(request, "job.html", active="jobs", job=job, sc=sc, refresh=job.status in jobs.ACTIVE)

    # ------------------------------------------------------------ settings and audit

    def tls_cert() -> Path | None:
        return tls_path / "cert.pem" if tls_path else None

    def settings_page(request: Request, s: Session, tab: str, status_code: int = 200, **ctx) -> HTMLResponse:
        return page(request, f"settings_{tab}.html", status_code, active="settings", tab=tab, **ctx)

    def collection_page(request: Request, s: Session, status_code: int = 200, **ctx) -> HTMLResponse:
        """Settings › Data collection: the default schedule, missed and failed runs, history and API discovery."""
        default = ctx.pop("collection", None) or sources.collection(s)
        runs, t = [], auth._now()
        while sources.valid_schedule(default, ("daily", "weekly")) and len(runs) < 3 and (t := sources.next_run(default, t)):
            runs.append(t)
        return settings_page(request, s, "collection", status_code, collection=default, runs=runs, days=sources.DAYS,
                             zones=sources.ZONES, conns=[r for r in connections(s) if r["sc"]],
                             general=ctx.pop("general", None) or {**jobs.GENERAL, **get_setting(s, "general")}, **ctx)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_collection(request: Request, msg: str = ""):
        with session() as s:
            return collection_page(request, s, msg=MESSAGES.get(msg))

    @app.post("/settings", response_class=HTMLResponse)
    async def settings_collection_save(request: Request):
        f = await checked_form(request)
        with session() as s:
            values = {k: f.get(k, "").strip() for k in jobs.GENERAL}
            default = {**sources.schedule_form(f), "catch_up": "catch_up" in f, "retry": "retry" in f}
            errors = [] if all(v.isdigit() and int(v) > 0 for v in values.values()) else ["Every number must be a whole number above 0"]
            if not sources.valid_schedule(default, ("daily", "weekly")):
                errors.append("Choose daily or weekly, a day, a time and a time zone")
            if errors:
                return collection_page(request, s, 422, general=values, collection=default, errors=errors)
            before = {**get_setting(s, "general"), **sources.collection(s)}
            put_setting(s, "general", {k: int(v) for k, v in values.items()})
            put_setting(s, "collection", default)
            for sc in s.query(SourceConfig):
                if (sc.settings.get("schedule") or {}).get("every") == "default":
                    sources.reschedule(sc, default)
            after = {**{k: int(v) for k, v in values.items()}, **default}
            audit(s, request, "settings changed", "data collection", changed=sorted(k for k in after if before.get(k) != after[k]))
            s.commit()
            return RedirectResponse("/settings?msg=collection", 303)

    def cert_info(path: Path) -> dict:
        c = x509.load_pem_x509_certificate(path.read_bytes())
        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = [str(n.value) for n in san]
        except x509.ExtensionNotFound:
            names = []
        return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(), "self_signed": c.issuer == c.subject,
                "names": names, "expires": c.not_valid_after_utc.date().isoformat(), "fingerprint": tls.fingerprint(path)}

    def security_page(request: Request, s: Session, status_code: int = 200, **ctx) -> HTMLResponse:
        current = cert_info(tls_path / "cert.pem") if tls_path and (tls_path / "cert.pem").exists() else None
        pending = bool(tls_path and (tls_path / "csr-key.pem").exists())
        return settings_page(request, s, "security", status_code, https=tls_path is not None, current=current, pending=pending,
                             idle=int(auth.IDLE.total_seconds() // 60), absolute=int(auth.ABSOLUTE.total_seconds() // 3600), **ctx)

    @app.get("/settings/security", response_class=HTMLResponse)
    def settings_security(request: Request, msg: str = ""):
        with session() as s:
            return security_page(request, s, msg=MESSAGES.get(msg))

    @app.post("/settings/security/csr", response_class=HTMLResponse)
    async def settings_csr(request: Request):
        f = await checked_form(request)
        with session() as s:
            if tls_path is None:
                raise HTTPException(404)
            names = [x for x in re.split(r"[\s,]+", f.get("names", "")) if x]
            ips, dns = [], []
            for n in names:
                (ips if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*", n) else dns).append(n)
            try:
                csr = tls.make_csr(tls_path, dns, ips).decode()
            except ValueError as e:
                return security_page(request, s, 422, errors=[str(e)], names=f.get("names", ""))
            audit(s, request, "https csr made", ", ".join(names))
            s.commit()
            return security_page(request, s, csr=csr)

    @app.post("/settings/security/install", response_class=HTMLResponse)
    async def settings_install(request: Request):
        f = await checked_form(request)
        with session() as s:
            if tls_path is None:
                raise HTTPException(404)
            try:
                fp = tls.install_cert(tls_path, f.get("chain", "").encode())
            except ValueError as e:
                return security_page(request, s, 422, errors=[str(e) or "Not a PEM certificate"], chain=f.get("chain", ""))
            if app.state.reload_tls:
                app.state.reload_tls()
            audit(s, request, "https certificate installed", fp)
            s.commit()
            return RedirectResponse("/settings/security?msg=installed", 303)

    @app.get("/settings/account", response_class=HTMLResponse)
    def settings_account(request: Request):
        with session() as s:
            return settings_page(request, s, "account")

    @app.post("/settings/account", response_class=HTMLResponse)
    async def settings_account_save(request: Request):
        f = await checked_form(request)
        with session() as s:
            errors = []
            if not auth.authenticate(s, request.state.user, f.get("current", "")):
                errors.append("The current password is wrong")
            if f.get("new", "") != f.get("again", ""):
                errors.append("The new passwords do not match")
            if not errors:
                try:
                    auth.set_password(s, request.state.user, f["new"])
                except ValueError as e:
                    errors.append(str(e).capitalize())
            if errors:
                s.rollback()
                return settings_page(request, s, "account", 422, errors=errors)
            audit(s, request, "password changed", request.state.user)
            s.commit()
        r = RedirectResponse("/login?changed=1", 303)
        r.delete_cookie(auth.COOKIE)
        return r

    @app.get("/settings/transfer", response_class=HTMLResponse)
    def settings_transfer(request: Request, msg: str = ""):
        with session() as s:
            return settings_page(request, s, "transfer", msg=MESSAGES.get(msg))

    @app.get("/settings/export.toml")
    def settings_export(request: Request):
        with session() as s:
            audit(s, request, "sources exported")
            s.commit()
            return Response(sources.export_toml(s), media_type="application/toml",
                            headers={"Content-Disposition": 'attachment; filename="waf-inventory-sources.toml"'})

    @app.post("/settings/import", response_class=HTMLResponse)
    async def settings_import(request: Request):
        f = await checked_form(request)
        with session() as s:
            try:
                entries = tomllib.loads(f.get("toml", "")).get("sources", [])
                added, skipped = sources.add_sources(s, entries, cfg["_dir"])
            except (tomllib.TOMLDecodeError, ValueError, TypeError, vault.VaultError) as e:
                s.rollback()
                return settings_page(request, s, "transfer", 422, errors=[f"Not imported: {e}"], toml=f.get("toml", ""))
            audit(s, request, "sources imported", ", ".join(added), skipped=skipped)
            s.commit()
            return settings_page(request, s, "transfer", result={"added": added, "skipped": skipped})

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, action: str = "", user: str = "", format: str = ""):
        with session() as s:
            q = s.query(AuditLog).order_by(AuditLog.id.desc())
            q = q.filter(AuditLog.action == action) if action else q
            q = q.filter(AuditLog.user == user) if user else q
            rows = q.limit(5000).all()
            if format == "csv":
                return Response(report.to_csv([{"time": r.time.isoformat(), "user": r.user, "ip": r.ip, "action": r.action,
                                                 "target": r.target, "detail": json.dumps(r.detail)} for r in rows]),
                                media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})
            actions = [a for (a,) in s.query(AuditLog.action).distinct().order_by(AuditLog.action)]
            users = [u for (u,) in s.query(AuditLog.user).distinct() if u]
            return settings_page(request, s, "audit", rows=rows[:500], actions=actions, users=users, action=action, who=user,
                                 query=str(request.query_params))

    # ------------------------------------------------------------ inventory

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        with session() as s:
            conns = connections(s)
            return page(request, "overview.html", problems=sources.problems(s, tls_cert()), active="", summary=report.summary(s),
                        plan=remedies.plan(s), trend=remedies.score_history(s), changes=report.table(s, "changes")[:5], conns=conns,
                        map=report.protection_map(s), last=max((r["inv"].last_run for r in conns if r["inv"] and r["inv"].last_run), default=None))

    @app.get("/findings", response_class=HTMLResponse)
    def fix_plan(request: Request):
        with session() as s:
            return page(request, "fix.html", active="findings", plan=remedies.plan(s), trend=remedies.score_history(s))

    @app.get("/changes", response_class=HTMLResponse)
    def changes_page(request: Request, weakened: str = "", source: str = ""):
        with session() as s:
            rows = report.table(s, "changes", source=source)
            return page(request, "changes.html", active="changes", rows=[r for r in rows if r["weakened"] or not weakened],
                        total=len(rows), weak=sum(bool(r["weakened"]) for r in rows), weakened=weakened, source=source,
                        sources=sorted({r["source"] for r in rows}))

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
            return page(request, "app.html", active="applications", host=host, listeners=listeners, endpoints=eps, findings=found,
                        verdict=report.verdict(listeners))

    @app.get("/search", response_class=HTMLResponse)
    def search(request: Request, q: str = ""):
        term = q.strip().lower()
        with session() as s:
            hits = {}
            if term:
                hits = {
                    "Applications": [(f"/apps/{a}", a, "") for a in sorted({r["application"] for r in report.table(s, "applications")})
                                     if term in a.lower()],
                    "WAF policies": [(f"/policy/{r['id']}", r["policy"], f"{r['vendor']} · {r['mode']}") for r in report.table(s, "policies")
                                     if term in r["policy"].lower()],
                    "API endpoints": [(f"/apps/{e.host}", f"{e.method} {e.host}{e.template}", e.kind) for e in s.query(Endpoint)
                                      if term in f"{e.method} {e.host}{e.template}".lower()][:100],
                    "Fix plan": [(f"/findings#i{n}", i["action"], f"{len(i['items'])} affected") for n, i in enumerate(remedies.plan(s)["issues"], 1)
                                 if term in i["action"].lower() or term in i["rule"] or any(term in x["subject"].lower() for x in i["items"])],
                }
                exact = [h for h in hits["Applications"] + hits["WAF policies"] if h[1].lower() == term]
                if len(exact) == 1:  # a full hostname or policy name goes straight to its page
                    return RedirectResponse(exact[0][0], status_code=303)
            return page(request, "search.html", active="search", q=q, hits=hits, total=sum(map(len, hits.values())))

    @app.get("/policy/{pid}", response_class=HTMLResponse)
    def policy_detail(pid: int, request: Request):
        with session() as s:
            p = s.get(WafPolicy, pid)
            if p is None:
                raise HTTPException(404)
            used = [l for l in s.query(Listener) if l.policy_id == pid or any(r.policy_id == pid for r in l.routes)]
            return page(request, "policy.html", active="policies", p=p, used=used,
                        raw=json.dumps(p.raw, indent=2, sort_keys=True)[:200_000])

    @app.get("/tuning", response_class=HTMLResponse)
    def tuning_page(request: Request, verdict: str = "", support_id: str = ""):
        with session() as s:
            hit, rows = tuning.support_lookup(s, support_id) if support_id.strip() else (None, tuning.groups(s))
            counts = {k: sum(g["verdict"] == k for g in rows) if k else len(rows) for k in ("", "false positive", "unsure", "attack")}
            approved = sum(g["decision"] == "approved" and g["proposal"] is not None for g in rows)
            back = "/tuning" + (f"?{request.url.query}" if request.url.query else "")
            return page(request, "tuning.html", active="tuning", rows=[g for g in rows if not verdict or g["verdict"] == verdict],
                        counts=counts, verdict=verdict, support_id=support_id, hit=hit, approved=approved, back=back)

    @app.post("/tuning/decide")
    async def tuning_decide(request: Request):
        f = await checked_form(request)
        if f.get("decision") not in ("approved", "rejected", "") or not f.get("key"):
            raise HTTPException(400)
        with session() as s:
            row = s.get(TuningDecision, f.get("key", ""))
            if f["decision"]:
                s.merge(TuningDecision(key=f.get("key", ""), decision=f["decision"], user=request.state.user, time=auth._now()))
            elif row:
                s.delete(row)
            audit(s, request, f"tuning {f['decision'] or 'undone'}", f.get("key", ""))
            s.commit()
        return RedirectResponse(safe_next(f.get("back")), 303)

    @app.get("/export/tuning-approved.json")
    def export_tuning_json():
        with session() as s:
            return Response(tuning.patch_json(s), media_type=MEDIA["json"],
                            headers={"Content-Disposition": 'attachment; filename="tuning-approved.json"'})

    @app.get("/export/tuning-approved.tf")
    def export_tuning_tf():
        with session() as s:
            return PlainTextResponse(tuning.terraform(s), headers={"Content-Disposition": 'attachment; filename="tuning-approved.tf"'})

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
