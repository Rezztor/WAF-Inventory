"""Dashboard: server-rendered pages over the inventory, with CSV / JSON / Excel / HTML / OpenAPI exports."""
from __future__ import annotations

import hmac
import json
import re
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from . import auth, findings, jobs, report, sources, tls, vault
from .models import AuditLog, Endpoint, Job, Listener, Source, SourceConfig, WafPolicy, connect, get_setting, put_setting

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
}
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

    async def checked_form(request: Request) -> dict[str, str]:
        """Form fields of a signed-in POST, after checking its CSRF token."""
        f = await form(request)
        if not request.state.csrf or not hmac.compare_digest(f.get("csrf", ""), request.state.csrf):
            raise HTTPException(403, "Invalid form token; reload the page and try again")
        return f

    def safe_next(target: str | None) -> str:
        return target if target and target.startswith("/") and not target.startswith("//") and "\\" not in target else "/"

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

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
        return page(request, "source.html", status_code, active="console_sources", sc=sc, new=sc.id is None,
                    title=sources.TYPES[sc.type][0], fields=sources.TYPES[sc.type][1], secrets=sources.secret_state(sc),
                    recent=recent, every=sources.EVERY, days=sources.DAYS, **ctx)

    def get_source(s: Session, sid: int) -> SourceConfig:
        sc = s.get(SourceConfig, sid)
        if sc is None:
            raise HTTPException(404)
        return sc

    @app.get("/sources", response_class=HTMLResponse)
    def sources_list(request: Request, msg: str = ""):
        with session() as s:
            inv = {x.name: x for x in s.query(Source)}
            active = {j.source: j for j in s.query(Job).filter(Job.status.in_(jobs.ACTIVE))}
            rows = [{"sc": sc, "title": sources.TYPES[sc.type][0], "inv": inv.get(sc.name), "job": active.get(sc.name),
                     "secrets": sources.secret_state(sc)} for sc in s.query(SourceConfig).order_by(SourceConfig.name)]
            return page(request, "sources.html", active="console_sources", rows=rows, types=sources.TYPES, msg=MESSAGES.get(msg),
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
        with session() as s:
            sc = SourceConfig(type=kind, name=f.get("name", "").strip(), settings=dict(sources.DEFAULTS.get(kind, {})))
            try:
                errors = ([] if sc.name else ["Name is required"]) + sources.apply_form(sc, f)
                if sc.name and s.query(SourceConfig).filter_by(name=sc.name).first():
                    errors.append("A source with that name already exists")
                if not errors and kind == "azure" and sc.settings.get("auth") == "certificate":
                    sources.make_azure_certificate(sc)
            except vault.VaultError as e:
                errors = [str(e)]
            if errors:
                return source_page(request, s, sc, 422, errors=errors)
            s.add(sc)
            audit(s, request, "source added", sc.name, type=kind, secrets=sorted(sources.secret_state(sc)))
            s.commit()
            return RedirectResponse(f"/sources/{sc.id}?msg=created", 303)

    @app.get("/sources/{sid}", response_class=HTMLResponse)
    def source_edit(sid: int, request: Request, msg: str = ""):
        with session() as s:
            return source_page(request, s, get_source(s, sid), msg=MESSAGES.get(msg))

    @app.post("/sources/{sid}")
    async def source_save(sid: int, request: Request):
        f = await checked_form(request)
        with session() as s:
            sc = get_source(s, sid)
            before = dict(sc.settings)
            try:
                errors = sources.apply_form(sc, f)
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
                  secrets=[x.key for x in sources.TYPES[sc.type][1] if x.kind == "secret" and f.get(x.key, "").strip()])
            s.commit()
            return RedirectResponse(f"/sources/{sid}?msg=saved", 303)

    def _test(sid: int, certificate: str) -> tuple[bool, list[str], dict | None]:  # in a worker thread: it waits on the network
        with session() as s:
            sc = get_source(s, sid)
            try:
                return True, *sources.test(cfg, sc, certificate)
            except Exception as e:
                return False, [sources.explain(e, sc)], None

    @app.post("/sources/{sid}/test", response_class=HTMLResponse)
    async def source_test(sid: int, request: Request):
        """Test connection. With certificate=certificate_next (rotation), a pass makes the new certificate the one in use."""
        f = await checked_form(request)
        certificate = "certificate_next" if f.get("certificate") == "certificate_next" else "certificate"
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
        with session() as s:
            host = get_source(s, sid).settings.get("host", "")
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

    @app.get("/settings", response_class=HTMLResponse)
    def settings_general(request: Request, msg: str = ""):
        with session() as s:
            return settings_page(request, s, "general", general={**jobs.GENERAL, **get_setting(s, "general")}, msg=MESSAGES.get(msg))

    @app.post("/settings", response_class=HTMLResponse)
    async def settings_general_save(request: Request):
        f = await checked_form(request)
        with session() as s:
            values = {k: f.get(k, "").strip() for k in jobs.GENERAL}
            if not all(v.isdigit() and int(v) > 0 for v in values.values()):
                return settings_page(request, s, "general", 422, general=values, errors=["Every value must be a whole number above 0"])
            before = get_setting(s, "general")
            put_setting(s, "general", {k: int(v) for k, v in values.items()})
            audit(s, request, "settings changed", "general", changed=sorted(k for k in values if before.get(k) != int(values[k])))
            s.commit()
            return RedirectResponse("/settings?msg=general", 303)

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
            return page(request, "overview.html", problems=sources.problems(s, tls_cert()), active="", summary=report.summary(s),
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
