"""waf-inv: collect | findings | serve | export | reset-password | tls."""
from __future__ import annotations

import argparse
import csv
import getpass
import glob
import json
import os
import sys
import tomllib
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from . import azure, baffinbay, discovery, f5, findings, report
from .models import Endpoint, Source, WafEvent, connect, now, put_setting, save_snapshot, source


def load_config(path: str) -> dict:
    cfg = tomllib.loads(Path(path).read_text()) if Path(path).exists() else {}  # optional: the container runs without one
    cfg["_dir"] = Path(path).resolve().parent
    return cfg


def _path(cfg: dict, p: str) -> Path:
    return (cfg["_dir"] / p) if not Path(p).is_absolute() else Path(p)


def read_observations(pattern: Path) -> list[dict]:
    """JSONL or CSV files with host, method, path, status, content_type, user_agent, hits, first_seen, last_seen."""
    rows = []
    for f in sorted(glob.glob(str(pattern))):
        with open(f, newline="") as fh:
            if f.endswith(".csv"):
                rows += list(csv.DictReader(fh))
            else:
                rows += [json.loads(line) for line in fh if line.strip()]
    return rows


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


def collect_source(session, cfg: dict, src: dict, save_raw: str | None = None, credential=None, password: str | None = None,
                   log: Callable[[str], None] = _stderr) -> str:
    """Collect one source into the inventory. `credential` / `password` come from the console's vault; without them
    Azure uses DefaultAzureCredential and F5 the environment variable named by password_env."""
    kind, name = src["type"], src["name"]
    observations = None
    if kind in ("azure", "azure_bundle"):
        if kind == "azure":
            if credential is None:
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
            arm = azure.Arm(credential, cloud=src.get("cloud", "public"))
            bundle = azure.fetch_bundle(arm, src.get("subscriptions", []))
            if src.get("log_workspaces"):
                observations = list(azure.fetch_observations(arm, src["log_workspaces"], src.get("log_days", 30)))
            if save_raw:
                Path(save_raw).mkdir(parents=True, exist_ok=True)
                (Path(save_raw) / f"{name}.json").write_text(json.dumps(bundle, indent=1))
        else:
            bundle = json.loads(_path(cfg, src["path"]).read_text())
        gateways, policies = azure.parse_bundle(bundle)
    elif kind == "f5_rest":
        password = password or os.environ.get(src.get("password_env", "F5_PASSWORD"))
        if not password:
            raise RuntimeError(f"set {src.get('password_env', 'F5_PASSWORD')} for {name}")
        client = f5.F5Client(f5.address(src["host"], src.get("port")), src["username"], password,
                             ca_cert=src.get("ca_pem") or src.get("ca_cert"), token=src.get("token", True))
        client.login()
        try:
            data, warnings = f5.fetch_rest(client, export=src.get("export", True))
        finally:
            client.logout()
        for w in warnings:
            log(f"warning: {w}")
        gateways, policies = f5.build(f5.only_partitions(data, src.get("partitions", [])))
    elif kind == "f5_ssh":  # the console reads the device over SSH and passes what it read
        if "data" not in src:
            raise ValueError(f"{name}: SSH sources are collected by the console, not from config.toml")
        gateways, policies = f5.build(f5.only_partitions(src["data"], src.get("partitions", [])))
    elif kind == "f5_offline":
        gateways, policies = f5.build(f5.load_offline(_path(cfg, src["path"])))
    elif kind in ("baffinbay", "baffinbay_bundle"):  # the console signs in and passes what it read, as f5_ssh does
        if kind == "baffinbay" and "bundle" not in src:
            raise ValueError(f"{name}: Baffin Bay connections are collected by the console, not from config.toml")
        bundle = src["bundle"] if kind == "baffinbay" else json.loads(_path(cfg, src["path"]).read_text())
        gateways, policies = baffinbay.build(bundle)
        for crs, rules in (bundle.get("core_rule_sets") or {}).items():  # modSecId -> the rule id exclusions name
            put_setting(session, f"crs:{crs}", rules)
        save_snapshot(session, name, kind, gateways, policies)
        n = store_events(session, name, kind, bundle.get("events", []))
        return f"{len(gateways)} proxy(ies), {len(policies)} WAF configuration(s), {n} new WAF event(s)"
    elif kind == "logs":
        gateways, policies = None, None
        if not glob.glob(str(_path(cfg, src["path"]))):
            raise FileNotFoundError(2, "No files match", str(_path(cfg, src["path"])))
        observations = read_observations(_path(cfg, src["path"]))
    else:
        raise ValueError(f"unknown source type {kind!r}")

    if gateways is not None:
        save_snapshot(session, name, kind, gateways, policies)
    msg = f"{len(gateways or [])} gateway(s), {len(policies or [])} polic(ies)"
    if observations is not None:
        n = store_endpoints(session, name, kind, observations, cfg.get("discovery", {}))
        msg += f", {len(observations)} log row(s) -> {n} endpoint(s)"
    return msg


def store_endpoints(session, name: str, kind: str, observations: list[dict], dcfg: dict) -> int:
    conf = discovery.Config(collapse_threshold=dcfg.get("collapse_threshold", 10), min_hits=dcfg.get("min_hits", 5),
                            overrides=dcfg.get("overrides", {}))
    src = source(session, name, kind)
    src.endpoints = [Endpoint(**e) for e in discovery.discover(observations, conf)]
    src.status, src.error, src.last_run = "ok", None, now()
    session.commit()
    return len(src.endpoints)


EVENT_DAYS = 35


def store_events(session, name: str, kind: str, events: list[dict]) -> int:
    """Add events not stored yet and drop those older than EVENT_DAYS before the newest. Returns how many were added."""
    src = source(session, name, kind)
    session.flush()
    have = {i for (i,) in session.query(WafEvent.id).filter_by(source_id=src.id)}
    rows = {e["id"]: baffinbay.event_row(e) for e in events if e.get("id") and e["id"] not in have}
    session.add_all(WafEvent(source_id=src.id, **r) for r in rows.values())
    session.flush()
    if newest := session.query(WafEvent.time).filter_by(source_id=src.id).order_by(WafEvent.time.desc()).limit(1).scalar():
        cutoff = (datetime.fromisoformat(newest.replace("Z", "+00:00")) - timedelta(days=EVENT_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
        session.query(WafEvent).filter(WafEvent.source_id == src.id, WafEvent.time < cutoff).delete()
    session.commit()
    return len(rows)


def last_event(session, name: str) -> str | None:
    """The id of a source's newest stored event: where the next collection carries on."""
    return session.query(WafEvent.id).join(Source, WafEvent.source_id == Source.id).filter(Source.name == name) \
        .order_by(WafEvent.time.desc()).limit(1).scalar()


def load_specs(cfg: dict) -> list[dict]:
    files = [f for p in cfg.get("discovery", {}).get("openapi_specs", []) for f in glob.glob(str(_path(cfg, p)))]
    return [json.loads(Path(f).read_text()) for f in sorted(files)]


def cmd_collect(args, cfg, session) -> int:
    from .models import SourceConfig
    if session.query(SourceConfig.id).first():  # sources managed in the console take over from config.toml
        from . import jobs
        runner = jobs.Runner(session.get_bind(), cfg, echo=True)
        failed = 0
        for sc in session.query(SourceConfig).order_by(SourceConfig.name):
            if not args.source or sc.name in args.source:
                job = runner.submit_now(session, sc, trigger="cli")
                failed += job.status != "ok"
        return 1 if failed else 0
    failed = 0
    for src in cfg.get("sources", []):
        if args.source and src["name"] not in args.source:
            continue
        print(f"[{src['name']}] collecting ({src['type']})")
        try:
            print(f"[{src['name']}] ok: {collect_source(session, cfg, src, args.save_raw)}")
        except Exception as e:  # one broken source must not stop the others
            session.rollback()
            failed += 1
            s = source(session, src["name"], src["type"])
            s.status, s.error, s.last_run = "error", f"{type(e).__name__}: {e}", now()
            session.commit()
            print(f"[{src['name']}] ERROR {type(e).__name__}: {e}", file=sys.stderr)
    cmd_findings(args, cfg, session)
    return 1 if failed else 0


def cmd_findings(args, cfg, session) -> int:
    out = findings.run(session, load_specs(cfg))
    counts = {sev: sum(f.severity == sev for f in out) for sev in ("high", "medium", "low")}
    print(f"findings: {counts}")
    return 0


def cmd_export(args, cfg, session) -> int:
    fmt = args.format
    if fmt == "openapi":
        hosts = args.host or sorted({h for (h,) in session.query(Endpoint.host).filter(Endpoint.kind == "api").distinct()})
        out = Path(args.out or "openapi")
        out.mkdir(parents=True, exist_ok=True)
        for h in hosts:
            (out / f"{h}.json").write_text(json.dumps(report.openapi_for(session, h), indent=2))
        print(f"wrote {len(hosts)} OpenAPI file(s) to {out}/")
        return 0
    if fmt == "html":
        data: str | bytes = report.to_html(session)
    elif fmt == "xlsx":
        data = report.to_xlsx(report.all_sheets(session) if not args.table else {args.table: report.table(session, args.table)})
    else:
        if fmt == "csv" and not args.table:
            sys.exit("csv export needs --table (one of: " + ", ".join(report.TABLES) + ")")
        rows = report.table(session, args.table) if args.table else report.all_sheets(session)
        data = report.to_csv(rows) if fmt == "csv" else report.to_json(rows)
    out = args.out or f"waf-inventory{'-' + args.table if args.table else ''}.{fmt}"
    Path(out).write_bytes(data if isinstance(data, bytes) else data.encode())
    print(f"wrote {out}")
    return 0


def cmd_serve(args, cfg, session) -> int:
    import uvicorn

    from . import auth, sources, tls
    from .web import create_app
    if not auth.has_users(session):
        sys.exit("No admin account yet. Create one first: waf-inv reset-password <username>")
    if n := sources.import_config(session, cfg):
        from .models import AuditLog
        session.add(AuditLog(time=auth._now(), user=None, ip=None, action="sources imported", target="config file", detail={"count": n}))
        session.commit()
        print(f"Imported {n} source(s) from the config file; they are managed in the console from now on", flush=True)
    ssl = {}
    if args.tls_dir:
        cert, key = tls.ensure_cert(Path(args.tls_dir))
        ssl = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        print(f"HTTPS certificate SHA-256 fingerprint: {tls.fingerprint(cert)}", flush=True)
    app = create_app(cfg["database"], cfg, tls_dir=args.tls_dir, background=True)
    config = uvicorn.Config(app, host=args.host, port=args.port, server_header=False, **ssl)
    if ssl:  # Settings > HTTPS installs a new certificate: load it into the live context, no restart
        app.state.reload_tls = lambda: config.ssl.load_cert_chain(ssl["ssl_certfile"], ssl["ssl_keyfile"])
    uvicorn.Server(config).run()
    return 0


def cmd_reset_password(args, cfg, session) -> int:
    """Create the user or set a new password. Also the recovery path: it needs shell access to the host."""
    from . import auth
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(f"New password for {args.username}: ")
        if getpass.getpass("Again: ") != password:
            sys.exit("passwords do not match")
    try:
        auth.set_password(session, args.username, password)
    except ValueError as e:
        sys.exit(str(e))
    print(f"password set for {args.username}; existing sessions signed out")
    return 0


def cmd_tls(args, cfg, session) -> int:
    from . import tls
    if not args.tls_dir:
        sys.exit("set WAF_INV_TLS_DIR or pass --tls-dir")
    folder = Path(args.tls_dir)
    try:
        if args.action == "csr":
            sys.stdout.write(tls.make_csr(folder, args.dns or [], args.ip or []).decode())
        elif args.action == "install":
            print(f"installed; SHA-256 fingerprint {tls.install_cert(folder, sys.stdin.buffer.read())}. Restart to use it.")
        else:
            print(f"SHA-256 fingerprint {tls.fingerprint(tls.ensure_cert(folder)[0])}")
    except ValueError as e:
        sys.exit(str(e))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="waf-inv", description=__doc__)
    ap.add_argument("-c", "--config", help="config file (default: $WAF_INV_CONFIG or config.toml; optional unless given here)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("collect", help="collect config + traffic from sources, then recompute findings")
    p.add_argument("--source", action="append", help="only this source (repeatable)")
    p.add_argument("--save-raw", metavar="DIR", help="also save the raw Azure bundle (for offline reuse)")
    sub.add_parser("findings", help="recompute findings")
    p = sub.add_parser("export", help="export the inventory")
    p.add_argument("-f", "--format", choices=["csv", "json", "xlsx", "html", "openapi"], default="xlsx")
    p.add_argument("-t", "--table", choices=report.TABLES)
    p.add_argument("--host", action="append", help="openapi: only this host (repeatable)")
    p.add_argument("-o", "--out")
    p = sub.add_parser("serve", help="run the dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    tls_dir = os.environ.get("WAF_INV_TLS_DIR")
    p.add_argument("--tls-dir", default=tls_dir, help="serve HTTPS with cert.pem/key.pem from here (self-signed if missing)")
    p = sub.add_parser("reset-password", help="create the admin account or set a new password")
    p.add_argument("username")
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    p = sub.add_parser("tls", help="HTTPS certificate: show it, make a CSR for your CA, install the signed certificate")
    p.add_argument("action", choices=["show", "csr", "install"])
    p.add_argument("--tls-dir", default=tls_dir)
    p.add_argument("--dns", action="append", help="csr: DNS name the console is reached on (repeatable)")
    p.add_argument("--ip", action="append", help="csr: IP address the console is reached on (repeatable)")
    args = ap.parse_args(argv)

    if args.config and not Path(args.config).exists():
        sys.exit(f"config file not found: {args.config}")
    cfg = load_config(args.config or os.environ.get("WAF_INV_CONFIG", "config.toml"))
    db = cfg.get("database", "waf_inventory.db")
    if "://" not in db and not Path(db).is_absolute():
        db = str(cfg["_dir"] / db)
    cfg["database"] = db
    session = connect(db)
    return {"collect": cmd_collect, "findings": cmd_findings, "export": cmd_export, "serve": cmd_serve,
            "reset-password": cmd_reset_password, "tls": cmd_tls}[args.cmd](args, cfg, session)


if __name__ == "__main__":
    sys.exit(main())
