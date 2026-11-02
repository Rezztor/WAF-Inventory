"""Baffin Bay Threat Protection (Mastercard): proxies and WAF settings from the Traffic Management API, WAF events from the
Event Insight API.

Read-only: GETs only, plus the client-credentials token request. A token lasts 24 hours and a new one can be issued
only once every 12 hours, so the caller keeps it (the console stores it encrypted) and hands it back on the next run.
The events API keeps 5 days and returns only requests that matched a rule, so events feed tuning, never API discovery.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

import httpx

from .models import Gateway, Listener, Route, WafPolicy

AUTH = "https://m2m-auth.baffinbay.com/oauth/token"
API = "https://portal.baffinbay.com"
MODE = {"BLOCK": "block", "LOG": "detect", "DISABLED": "off"}
KIND = {"httpProxy": "proxy", "l4Proxy": "l4proxy", "routedDsr": "dsr"}
MAX_PAGES = 2000  # shortcut: 200,000 events per run at 100 a page; page further on the next run if a tenant ever has more


class Client:
    """Bearer token from client credentials, reused until an hour before it expires; 429 and 5xx backoff."""

    def __init__(self, client_id: str, client_secret: str, token: dict | None = None, http: httpx.Client | None = None):
        self.id, self.secret, self.token = client_id, client_secret, token  # token: {"access_token", "expires"}
        self.http = http or httpx.Client(timeout=60)

    def _bearer(self) -> str:
        if not self.token or datetime.fromisoformat(self.token["expires"]) < datetime.now(timezone.utc) + timedelta(hours=1):
            r = self.http.post(AUTH, json={"client_id": self.id, "client_secret": self.secret, "grant_type": "client_credentials",
                                           "audience": API})
            r.raise_for_status()
            b = r.json()
            expires = datetime.now(timezone.utc) + timedelta(seconds=int(b.get("expires_in", 86400)))
            self.token = {"access_token": b["access_token"], "expires": expires.isoformat(timespec="seconds")}
        return self.token["access_token"]

    def get(self, path: str, params: dict | None = None) -> dict:
        for attempt in range(6):
            r = self.http.get(API + path, params=params, headers={"Authorization": f"Bearer {self._bearer()}",
                                                                  "Accept": "application/vnd.api+json"})
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 60))
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()
        return r.json()

    def events(self, tenant: str, after: str | None = None) -> Iterator[dict]:
        """WAF events oldest first, from just after the `after` event id (or the oldest the API keeps)."""
        params = {"filter[tenantId]": tenant, "filter[eventType]": "WAF_EVENT", "page[size]": 100}
        if after:
            params["page[after]"] = after
        for _ in range(MAX_PAGES):
            body = self.get("/api/v2/insight/http-security-events", params)
            yield from body.get("data", [])
            nxt = (body.get("links") or {}).get("next")
            if not body.get("data") or not nxt:
                return
            params = {"filter[tenantId]": tenant, "filter[eventType]": "WAF_EVENT", **dict(parse_qsl(urlsplit(nxt).query))}


def fetch(c: Client, tenant: str, after: str | None = None) -> dict:
    """Everything one collection needs, in the offline bundle's shape."""
    configs = c.get("/api/v2/traffic-mgmt/traffic-configs", {"filter[tenant]": tenant, "include": "managedConfig"})
    catalogue = {}
    for crs in sorted({v for v in _resolved(configs).values() if v}):
        rules = c.get(f"/api/v2/traffic-mgmt/core-rule-sets/{crs}")
        rules = (rules.get("data") or {}).get("attributes", rules.get("data", rules))
        catalogue[crs] = {r["modSecId"]: r["id"] for r in rules.get("rules", []) if r.get("modSecId") and r.get("id")}
    try:
        events = list(c.events(tenant, after))
    except httpx.HTTPStatusError as e:  # the cursor event has aged out of the API's 5 days: start from its oldest
        if not after or e.response.status_code not in (400, 404):
            raise
        events = list(c.events(tenant))
    return {"traffic_configs": configs, "core_rule_sets": catalogue, "events": events}


def _resolved(configs: dict) -> dict[str, str]:
    """managedConfig id -> resolved CRS id, e.g. crs-v4.22.0."""
    out = {}
    for inc in configs.get("included", []):
        d = inc.get("data", inc)
        out[d.get("id")] = ((d.get("attributes") or {}).get("waf") or {}).get("coreRuleSet", {}).get("resolvedId")
    return out


# ---------------------------------------------------------------- inventory

def build(bundle: dict) -> tuple[list[Gateway], list[WafPolicy]]:
    configs = bundle.get("traffic_configs") or {}
    resolved = _resolved(configs)
    gateways, policies = [], []
    for item in configs.get("data", []):
        a, kind = item.get("attributes") or {}, item.get("type", "httpProxy")
        mc = (((item.get("relationships") or {}).get("managedConfig") or {}).get("data") or {}).get("id")
        gw = Gateway(vendor="baffinbay", kind=KIND.get(kind, kind), name=a.get("name") or item["id"], native_id=item["id"],
                     version=a.get("version"))
        fe = a.get("frontend") or {}
        secure = fe.get("connectionType") == "SECURE"
        lst = Listener(name="frontend", protocol=("https" if secure else "http") if kind == "httpProxy" else "tcp",
                       address=fe.get("ipv4") or fe.get("ipv6"), port=fe.get("port"),
                       hostnames=[h["host"].lower() for h in fe.get("hosts", []) if h.get("host")],
                       waf_capable=kind == "httpProxy", native_id=item["id"])
        gw.listeners.append(lst)
        gateways.append(gw)
        if kind != "httpProxy":
            continue
        pol = WafPolicy(vendor="baffinbay", name=gw.name, native_id=item["id"], raw=item,
                        mode=MODE.get((a.get("waf") or {}).get("enforcement"), "off"), settings=settings(a, resolved.get(mc)))
        policies.append(pol)
        lst.policy = pol
        for rule in a.get("trafficRules", []):  # first match, in order, before the proxy's own backends
            act = rule.get("actions") or {}
            for cond in rule.get("matchingConditions", []):
                hosts = cond.get("hosts") or {}
                lst.routes.append(Route(name=rule.get("name", ""), hosts=hosts.get("values", []) if hosts.get("type") == "SELECT" else [],
                                        paths=[p.replace("{*}", "*") for p in cond.get("paths", [])], policy=pol,
                                        backend=_backend(rule.get("name", ""), act.get("setBackends")) if act.get("setBackends")
                                        else {"name": f"redirect to {act['setRedirect'].get('url')}"} if act.get("setRedirect") else None))
        lst.routes.append(Route(name="default", paths=["/*"], policy=pol, backend=_backend("backend", (a.get("backend") or {}).get("hosts"))))
    return gateways, policies


def _backend(name: str, hosts: list[dict] | None) -> dict:
    return {"name": name, "members": [f"{h.get('address')}:{h.get('port')}" for h in hosts or []]}


RISKY_METHODS = {"TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH",
                 "BPROPFIND", "BPROPPATCH", "BMOVE", "BDELETE", "BCOPY", "X-MS-ENUMATTS", "RPC_IN_DATA", "RPC_OUT_DATA"}


def settings(a: dict, crs: str | None) -> dict:
    """A proxy's settings in the shape the findings and the policy pages read (see README "Baffin Bay")."""
    waf, fe, be = a.get("waf") or {}, a.get("frontend") or {}, a.get("backend") or {}
    hc = waf.get("httpCompliance") or {}
    paths, cookies = waf.get("pathExclusions", []), waf.get("cookieExclusions", [])
    src = waf.get("sourceExclusions") or {}
    staged = waf.get("stagedWaf") or {}
    rl = a.get("rateLimiting") or {}
    acl = a.get("ipBasedAccessControl") or {}
    tls = be.get("tlsSettings")
    verify = ((tls or {}).get("verifyCertificate") or {}).get("mode")
    geo = a.get("geoFencing") or {}
    allowed = a.get("allowedSources") or {}
    requested = (waf.get("coreRuleSet") or {}).get("version")
    return {
        "paranoia_level": waf.get("paranoidLevel"),
        "rulesets": [{"type": "CRS", "version": (crs or "").removeprefix("crs-v") or requested, "requested": requested}],
        "crs_id": crs,
        "deployed": (a.get("deployment") or {}).get("state") != "UNDEPLOYED",
        "bot": (a.get("botProtection") or {}).get("strategy", "DISABLED") != "DISABLED",
        "matched_data": bool(waf.get("matchedDataEnabled")),
        "disabled_rules": [f"path {e['match']}: all rules" for e in paths if e.get("disableAll")]
                          + [f"cookie {e['cookieName']}: all rules" for e in cookies if e.get("excludeAllRules")],
        "exclusions": [{"variable": "path", "selector": e.get("match"), "rules": [r.get("id") for r in e.get("rules", [])],
                        "scope": "all rules" if e.get("disableAll") else "rules"} for e in paths]
                      + [{"variable": "cookie", "selector": e.get("cookieName"), "rules": [r.get("id") for r in e.get("excludedRules", [])],
                          "scope": "all rules" if e.get("excludeAllRules") else "rules"} for e in cookies],
        "source_exclusions": src.get("sources", []) if src.get("enabled") else [],
        "allowed_methods": (hc.get("globalConfig") or {}).get("allowedHttpMethods", []),
        "body_parsing_off": [m.get("path") for rc in hc.get("resourceConfigs", []) for m in rc.get("matches", [])
                             if False in ((rc.get("config") or {}).get(k) for k in ("parseJsonEnabled", "parseXmlEnabled",
                                                                                    "parseMultipartRequestEnabled"))],
        "request_body_check": not any(False in ((rc.get("config") or {}).get(k) for k in ("parseJsonEnabled", "parseXmlEnabled",
                                                                                          "parseMultipartRequestEnabled"))
                                      for rc in hc.get("resourceConfigs", [])),
        "staged_waf": {"mode": staged.get("mode"), "paranoia_level": staged.get("paranoiaLevel"),
                       "crs": (staged.get("coreRuleSet") or {}).get("version"),
                       "exclusions": len(staged.get("pathExclusions", [])) + len(staged.get("cookieExclusions", []))}
                      if staged.get("state") == "ENABLED" else None,
        "rate_limits": [{"name": name, "rate": f"{(x.get('rate') or {}).get('value')} {(x.get('rate') or {}).get('unit')}",
                         "burst": x.get("burst")} for name, key in (("per source IP", "bySrcIp"), ("per source IP and URL", "bySrcIpAndUrl"))
                        if (x := rl.get(key) or {}).get("enforcement") == "BLOCK"],
        "geo": [f"{geo.get('type')}: {r}" for r in geo.get("regions", [])],
        "ip_lists": [f"{r.get('policy')}: {r.get('address')}" for r in (acl.get("rules") or {}).get("ipRanges", [])]
                    + [f"{r.get('policy')}: IP list {r.get('id')}" for r in (acl.get("rules") or {}).get("ipLists", [])],
        "allowed_sources": allowed.get("sources", []) if allowed.get("enforcement") == "ENABLED" else [],
        "frontend_tls": fe.get("connectionType") == "SECURE",
        "hsts": bool((fe.get("httpStrictTransportSecurity") or {}).get("enabled")) if fe.get("connectionType") == "SECURE" else None,
        "backend_tls": "plaintext" if tls is None else {"SYSTEM_TRUSTSTORE": "verified (system CAs)",
                                                         "CUSTOM_TRUSTSTORE": "verified (own CA)"}.get(verify, "not verified"),
    }


# ---------------------------------------------------------------- events

def event_row(e: dict) -> dict:
    """One stored event from an API event. Headers are reduced to Host and User-Agent; nothing else is kept."""
    a = e.get("attributes") or {}
    req, src = a.get("request") or {}, a.get("source") or {}
    head = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in req.get("headers", []))}
    return {"id": e["id"], "time": a.get("timestamp"),
            "proxy": ((((e.get("relationships") or {}).get("belongsTo") or {}).get("data")) or {}).get("id"),
            "host": head.get("host", "").split(":")[0].lower(), "method": req.get("method"), "path": (req.get("path") or "/").split("?")[0],
            "status": req.get("statusCode"), "action": a.get("action"), "instance": a.get("instance") or "main",
            "rules": [{"id": str(r.get("modSecId")), "name": r.get("name")} for r in a.get("rules", [])],
            "matched": [str(m["value"])[:200] for r in a.get("rules", []) if (m := r.get("matchedData") or {}).get("value") is not None],
            "source_ip": src.get("ip"), "country": src.get("countryCode"), "user_agent": head.get("user-agent", "")[:300],
            "support_id": (a.get("supportId") or "").replace("-", "").lower() or None}
