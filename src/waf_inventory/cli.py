"""waf-inv: collect | findings | serve | export."""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
import tomllib
from pathlib import Path

from . import azure, discovery, f5, findings, report
from .models import Endpoint, connect, now, save_snapshot, source


def load_config(path: str) -> dict:
    cfg = tomllib.loads(Path(path).read_text())
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


def collect_source(session, cfg: dict, src: dict, save_raw: str | None = None) -> str:
    kind, name = src["type"], src["name"]
    observations = None
    if kind in ("azure", "azure_bundle"):
        if kind == "azure":
            from azure.identity import DefaultAzureCredential
            arm = azure.Arm(DefaultAzureCredential())
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
        password = os.environ.get(src.get("password_env", "F5_PASSWORD"))
        if not password:
            raise RuntimeError(f"set {src.get('password_env', 'F5_PASSWORD')} for {name}")
        client = f5.F5Client(src["host"], src["username"], password, ca_cert=src.get("ca_cert"))
        client.login()
        try:
            data, warnings = f5.fetch_rest(client, export=src.get("export", True))
        finally:
            client.logout()
        for w in warnings:
            print(f"  warning: {w}", file=sys.stderr)
        gateways, policies = f5.build(data)
    elif kind == "f5_offline":
        gateways, policies = f5.build(f5.load_offline(_path(cfg, src["path"])))
    elif kind == "logs":
        gateways, policies = None, None
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


def load_specs(cfg: dict) -> list[dict]:
    files = [f for p in cfg.get("discovery", {}).get("openapi_specs", []) for f in glob.glob(str(_path(cfg, p)))]
    return [json.loads(Path(f).read_text()) for f in sorted(files)]


def cmd_collect(args, cfg, session) -> int:
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

    from .web import create_app
    uvicorn.run(create_app(cfg["database"]), host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="waf-inv", description=__doc__)
    ap.add_argument("-c", "--config", default=os.environ.get("WAF_INV_CONFIG", "config.toml"))
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
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    db = cfg.get("database", "waf_inventory.db")
    if "://" not in db and not Path(db).is_absolute():
        db = str(cfg["_dir"] / db)
    cfg["database"] = db
    session = connect(db)
    return {"collect": cmd_collect, "findings": cmd_findings, "export": cmd_export, "serve": cmd_serve}[args.cmd](args, cfg, session)


if __name__ == "__main__":
    sys.exit(main())
