"""Azure WAF: Application Gateway v2 + Front Door Standard/Premium config (ARM REST) and access logs (Log Analytics).

Everything is read-only GETs except the Log Analytics query, which is a read-only POST.
Parsing works on ARM REST JSON (with a `properties` wrapper) and on `az ... list` output (flattened).
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Iterator

import httpx

from .models import Gateway, Listener, Route, WafPolicy

ARM = "https://management.azure.com"
LOGS = "https://api.loganalytics.io"
API = {
    "subscriptions": "2022-12-01",
    "network": "2024-05-01",  # applicationGateways + ApplicationGatewayWebApplicationFirewallPolicies
    "cdn": "2024-02-01",  # Front Door Standard/Premium (Microsoft.Cdn/profiles/*)
    "fd_waf": "2024-02-01",  # Microsoft.Network/FrontDoorWebApplicationFirewallPolicies
}
MODE = {"prevention": "block", "detection": "detect"}


# ---------------------------------------------------------------- live collection

class Arm:
    """Minimal ARM/Log Analytics REST client: bearer token, nextLink paging, 429 backoff."""

    def __init__(self, credential, http: httpx.Client | None = None):
        self.cred = credential
        self.http = http or httpx.Client(timeout=120)

    def _send(self, method: str, url: str, scope: str, **kw) -> dict:
        for attempt in range(6):
            token = self.cred.get_token(f"{scope}/.default").token
            r = self.http.request(method, url, headers={"Authorization": f"Bearer {token}"}, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 60))
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()
        return r.json()

    def list(self, path: str, api: str) -> Iterator[dict]:
        url = f"{ARM}{path}?api-version={api}"
        while url:
            body = self._send("GET", url, ARM)
            yield from body.get("value", [])
            url = body.get("nextLink")

    def query_logs(self, workspace: str, kql: str, days: int) -> list[dict]:
        body = self._send("POST", f"{LOGS}/v1/workspaces/{workspace}/query", LOGS,
                          json={"query": kql, "timespan": f"P{days}D"})
        rows = []
        for t in body.get("tables", []):
            cols = [c["name"] for c in t["columns"]]
            rows += [dict(zip(cols, r, strict=True)) for r in t["rows"]]
        return rows


def fetch_bundle(arm: Arm, subscriptions: Iterable[str] = ()) -> dict:
    """Pull everything needed for the inventory into one JSON-serialisable bundle."""
    subs = list(subscriptions) or [s["subscriptionId"] for s in arm.list("/subscriptions", API["subscriptions"])]
    b = {"appgws": [], "appgw_policies": [], "afd_profiles": [], "afd_policies": []}
    for sub in subs:
        p = f"/subscriptions/{sub}/providers"
        b["appgws"] += arm.list(f"{p}/Microsoft.Network/applicationGateways", API["network"])
        b["appgw_policies"] += arm.list(f"{p}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies", API["network"])
        b["afd_policies"] += arm.list(f"{p}/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies", API["fd_waf"])
        for prof in arm.list(f"{p}/Microsoft.Cdn/profiles", API["cdn"]):
            if "AzureFrontDoor" not in prof.get("sku", {}).get("name", ""):
                continue  # classic CDN profiles have no WAF
            pid, api = prof["id"], API["cdn"]
            endpoints = list(arm.list(f"{pid}/afdEndpoints", api))
            groups = list(arm.list(f"{pid}/originGroups", api))
            for g in groups:
                g["origins"] = list(arm.list(f"{g['id']}/origins", api))
            b["afd_profiles"].append({
                "profile": prof,
                "endpoints": endpoints,
                "customDomains": list(arm.list(f"{pid}/customDomains", api)),
                "routes": [r for e in endpoints for r in arm.list(f"{e['id']}/routes", api)],
                "originGroups": groups,
                "securityPolicies": list(arm.list(f"{pid}/securityPolicies", api)),
            })
    return b


# Access logs from App Gateway (resource-specific and AzureDiagnostics) and Front Door Std/Premium,
# aggregated in the workspace so only one row per (host, method, path, query names, status, content type) comes back.
ACCESS_KQL = r"""
union isfuzzy=true
 (AGWAccessLogs
  | project TimeGenerated, Host = tostring(column_ifexists("Host", "")), Method = tostring(column_ifexists("HttpMethod", "")),
            Uri = tostring(column_ifexists("RequestUri", "")), Status = toint(column_ifexists("HttpStatus", 0)),
            ContentType = tostring(column_ifexists("ContentType", "")), UserAgent = tostring(column_ifexists("UserAgent", ""))),
 (AzureDiagnostics | where Category == "ApplicationGatewayAccessLog"
  | extend q = tostring(column_ifexists("requestQuery_s", ""))
  | project TimeGenerated, Host = tostring(column_ifexists("host_s", "")), Method = tostring(column_ifexists("httpMethod_s", "")),
            Uri = strcat(tostring(column_ifexists("requestUri_s", "")), iff(isempty(q), "", strcat("?", q))),
            Status = toint(column_ifexists("httpStatus_d", 0)), ContentType = "", UserAgent = tostring(column_ifexists("userAgent_s", ""))),
 (AzureDiagnostics | where Category == "FrontDoorAccessLog"
  | extend u = tostring(column_ifexists("requestUri_s", ""))
  | project TimeGenerated, Host = tostring(column_ifexists("hostName_s", "")), Method = tostring(column_ifexists("httpMethod_s", "")),
            Uri = substring(u, indexof(u, "/", 8)), Status = toint(column_ifexists("httpStatusCode_s", "0")),
            ContentType = "", UserAgent = tostring(column_ifexists("userAgent_s", "")))
| extend Path = tostring(split(Uri, "?")[0]), QueryNames = strcat_array(array_sort_asc(extract_all(@"[?&]([^=&#]+)", Uri)), ",")
| summarize Hits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), UserAgent = take_any(UserAgent)
    by Host = tolower(Host), Method, Path, QueryNames, Status, ContentType
| take 500000
"""  # ponytail: one capped query per workspace; split by day if a workspace exceeds the API result limits


def fetch_observations(arm: Arm, workspaces: Iterable[str], days: int = 30) -> Iterator[dict]:
    for ws in workspaces:
        for r in arm.query_logs(ws, ACCESS_KQL, days):
            q = r.get("QueryNames") or ""
            yield {
                "host": r["Host"], "method": r["Method"],
                "path": r["Path"] + (("?" + "&".join(f"{n}=" for n in q.split(","))) if q else ""),
                "status": r.get("Status"), "content_type": r.get("ContentType"), "user_agent": r.get("UserAgent"),
                "hits": r.get("Hits", 1), "first_seen": r.get("FirstSeen"), "last_seen": r.get("LastSeen"),
            }


# ---------------------------------------------------------------- parsing

def _p(o: dict | None) -> dict:
    return (o or {}).get("properties", o or {})


def _id(ref: dict | str | None) -> str | None:
    if isinstance(ref, dict):
        ref = ref.get("id")
    return ref.lower() if ref else None


def _last(rid: str | None) -> str | None:
    return rid.rstrip("/").rsplit("/", 1)[-1] if rid else None


def parse_bundle(b: dict) -> tuple[list[Gateway], list[WafPolicy]]:
    policies = {_id(p): normalize_appgw_policy(p) for p in b.get("appgw_policies", [])}
    policies |= {_id(p): normalize_afd_policy(p) for p in b.get("afd_policies", [])}

    gateways = [parse_appgw(g, policies) for g in b.get("appgws", [])]
    gateways += [parse_afd(p, policies) for p in b.get("afd_profiles", [])]
    return gateways, list(policies.values())


def _resolve(policies: dict, ref) -> WafPolicy | None:
    pid = _id(ref)
    if pid and pid not in policies:  # referenced but not readable (other subscription / no access)
        policies[pid] = WafPolicy(vendor="azure", name=_last(pid), native_id=pid, mode="unknown",
                                  settings={"note": "policy referenced but not readable with current credentials"})
    return policies.get(pid)


def parse_appgw(gw: dict, policies: dict) -> Gateway:
    p = _p(gw)
    g = Gateway(vendor="azure", kind="appgw", name=gw["name"], native_id=_id(gw), location=gw.get("location"),
                version=(p.get("sku") or {}).get("tier"))
    def resolve(ref):
        return _resolve(policies, ref)

    gw_policy = resolve(p.get("firewallPolicy"))
    if gw_policy is None and p.get("webApplicationFirewallConfiguration"):
        gw_policy = normalize_legacy_waf(gw["name"], gw["id"], p["webApplicationFirewallConfiguration"])
        policies[gw_policy.native_id] = gw_policy
    ports = {_id(x): _p(x).get("port") for x in p.get("frontendPorts", [])}
    ips = {_id(x): _p(x).get("privateIPAddress") or _last(_id(_p(x).get("publicIPAddress"))) for x in p.get("frontendIPConfigurations", [])}
    pools = {_id(x): {"name": x["name"], "members": [a.get("fqdn") or a.get("ipAddress") for a in _p(x).get("backendAddresses", [])]}
             for x in p.get("backendAddressPools", [])}
    pathmaps = {_id(x): _p(x) for x in p.get("urlPathMaps", [])}

    listeners = {}
    for item in p.get("httpListeners", []):
        lp = _p(item)
        hosts = lp.get("hostNames") or ([lp["hostName"]] if lp.get("hostName") else [])
        lst = Listener(name=item["name"], protocol=(lp.get("protocol") or "").lower(), native_id=_id(item),
                       address=ips.get(_id(lp.get("frontendIPConfiguration"))), port=ports.get(_id(lp.get("frontendPort"))),
                       hostnames=[h.lower() for h in hosts], policy=resolve(lp.get("firewallPolicy")) or gw_policy)
        listeners[_id(item)] = lst
        g.listeners.append(lst)
    for item in p.get("listeners", []):  # L4 TCP/TLS proxy listeners are never WAF-inspected
        lp = _p(item)
        g.listeners.append(Listener(name=item["name"], protocol=(lp.get("protocol") or "tcp").lower(), native_id=_id(item),
                                    address=ips.get(_id(lp.get("frontendIPConfiguration"))),
                                    port=ports.get(_id(lp.get("frontendPort"))), waf_capable=False))

    for rule in sorted(p.get("requestRoutingRules", []), key=lambda r: _p(r).get("priority") or 0):
        rp, name = _p(rule), rule["name"]
        lst = listeners.get(_id(rp.get("httpListener")))
        if lst is None:
            continue
        if rp.get("redirectConfiguration"):
            lst.routes.append(Route(name=name, paths=["/*"], backend={"name": "redirect:" + _last(_id(rp["redirectConfiguration"]))},
                                    policy=lst.policy))
            continue
        pm = pathmaps.get(_id(rp.get("urlPathMap")))
        if pm is None:
            lst.routes.append(Route(name=name, paths=["/*"], backend=pools.get(_id(rp.get("backendAddressPool"))), policy=lst.policy))
            continue
        for pr in pm.get("pathRules", []):
            prp = _p(pr)
            lst.routes.append(Route(name=f"{name}/{pr['name']}", paths=prp.get("paths", []),
                                    backend=pools.get(_id(prp.get("backendAddressPool"))),
                                    policy=resolve(prp.get("firewallPolicy")) or lst.policy))
        lst.routes.append(Route(name=f"{name}/default", paths=["/*"], backend=pools.get(_id(pm.get("defaultBackendAddressPool"))),
                                policy=lst.policy))
    return g


def parse_afd(bundle: dict, policies: dict) -> Gateway:
    prof = bundle["profile"]
    g = Gateway(vendor="azure", kind="afd", name=prof["name"], native_id=_id(prof), location=prof.get("location"),
                version=(prof.get("sku") or {}).get("name"))
    domain_policy = {}
    for sp in bundle.get("securityPolicies", []):
        par = _p(sp).get("parameters", {})
        if par.get("type") != "WebApplicationFirewall":
            continue
        pol = _resolve(policies, par.get("wafPolicy"))
        for assoc in par.get("associations", []):
            for d in assoc.get("domains", []):
                domain_policy[_id(d)] = pol
    domains = {}
    for d in bundle.get("endpoints", []) + bundle.get("customDomains", []):
        host = _p(d).get("hostName", "").lower()
        domains[_id(d)] = lst = Listener(name=d["name"], protocol="https", port=443, hostnames=[host], native_id=_id(d),
                                         policy=domain_policy.get(_id(d)))
        g.listeners.append(lst)
    groups = {_id(og): {"name": og["name"], "members": [_p(o).get("hostName") for o in og.get("origins", [])]}
              for og in bundle.get("originGroups", [])}
    for r in bundle.get("routes", []):
        rp = _p(r)
        if rp.get("enabledState") == "Disabled":
            continue
        doms = [_id(d) for d in rp.get("customDomains", [])]
        if rp.get("linkToDefaultDomain") == "Enabled":
            doms.append(_id(r).split("/routes/")[0])
        for d in doms:
            if lst := domains.get(d):
                lst.routes.append(Route(name=r["name"], paths=rp.get("patternsToMatch", ["/*"]),
                                        backend=groups.get(_id(rp.get("originGroup"))), policy=lst.policy))
    return g


# ---------------------------------------------------------------- policy normalization

def _conditions(rule: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (readable conditions, geo values, ip values) for AppGW or AFD custom rule match conditions."""
    text, geo, ips = [], [], []
    for c in rule.get("matchConditions", []):
        variables = c.get("matchVariables") or [{"variableName": c.get("matchVariable"), "selector": c.get("selector")}]
        var = ",".join(v["variableName"] + (f"[{v['selector']}]" if v.get("selector") else "") for v in variables)
        values = c.get("matchValues") or c.get("matchValue") or []
        neg = "not " if c.get("negationConditon") or c.get("negateCondition") else ""
        text.append(f"{var} {neg}{c.get('operator')} {', '.join(map(str, values[:10]))}{' …' if len(values) > 10 else ''}")
        if c.get("operator") == "GeoMatch":
            geo += values
        if c.get("operator") == "IPMatch":
            ips += values
    return text, geo, ips


def _custom_rules(rules: list[dict]) -> dict:
    out = {"custom_rules": [], "rate_limits": [], "geo": [], "ip_lists": []}
    for r in rules:
        cond, geo, ips = _conditions(r)
        enabled = (r.get("state") or r.get("enabledState") or "Enabled") == "Enabled"
        rule = {"name": r.get("name"), "priority": r.get("priority"), "type": r.get("ruleType"), "action": r.get("action"),
                "enabled": enabled, "conditions": cond}
        out["custom_rules"].append(rule)
        if r.get("ruleType") == "RateLimitRule":
            out["rate_limits"].append({"name": r.get("name"), "threshold": r.get("rateLimitThreshold"),
                                       "minutes": r.get("rateLimitDurationInMinutes") or r.get("rateLimitDuration"),
                                       "group_by": r.get("groupByUserSession") or r.get("groupBy")})
        if enabled:
            out["geo"] += [f"{r.get('action')}: {v}" for v in geo]
            out["ip_lists"] += [f"{r.get('action')}: {v}" for v in ips]
    return out


def _exclusions(items: list[dict], scope: str = "") -> list[dict]:
    return [{"variable": e.get("matchVariable"), "operator": e.get("selectorMatchOperator"), "selector": e.get("selector"),
             "scope": scope or "policy"} for e in items]


def normalize_appgw_policy(raw: dict) -> WafPolicy:
    p = _p(raw)
    s, mr = p.get("policySettings", {}), p.get("managedRules", {})
    mode = "off" if s.get("state") == "Disabled" else MODE.get((s.get("mode") or "").lower(), "unknown")
    sets = mr.get("managedRuleSets", [])
    disabled, exclusions = [], _exclusions(mr.get("exclusions", []))
    for rs in sets:
        for go in rs.get("ruleGroupOverrides", []):
            disabled += [f"{rs['ruleSetType']}:{r['ruleId']}" for r in go.get("rules", []) if r.get("state") == "Disabled"]
    for c in p.get("computedDisabledRules", []) or []:
        disabled += [f"{c.get('ruleGroupName')}:{r}" for r in c.get("rules", [])]
    settings = {
        "rulesets": [{"type": r["ruleSetType"], "version": r["ruleSetVersion"]} for r in sets],
        "bot": any("BotManager" in r["ruleSetType"] for r in sets),
        "disabled_rules": sorted(set(disabled)),
        "exclusions": exclusions,
        "size_limits": {k: s.get(k) for k in ("requestBodyCheck", "requestBodyEnforcement", "requestBodyInspectLimitInKB",
                                               "maxRequestBodySizeInKb", "fileUploadEnforcement", "fileUploadLimitInMb") if k in s},
        "request_body_check": s.get("requestBodyCheck", True),
        **_custom_rules(p.get("customRules", [])),
    }
    return WafPolicy(vendor="azure", name=raw["name"], native_id=_id(raw), mode=mode, settings=settings, raw=raw)


def normalize_afd_policy(raw: dict) -> WafPolicy:
    p = _p(raw)
    s, sets = p.get("policySettings", {}), p.get("managedRules", {}).get("managedRuleSets", [])
    mode = "off" if s.get("enabledState") == "Disabled" else MODE.get((s.get("mode") or "").lower(), "unknown")
    disabled, exclusions = [], []
    for rs in sets:
        exclusions += _exclusions(rs.get("exclusions", []), rs["ruleSetType"])
        for go in rs.get("ruleGroupOverrides", []):
            exclusions += _exclusions(go.get("exclusions", []), go.get("ruleGroupName", ""))
            for r in go.get("rules", []):
                exclusions += _exclusions(r.get("exclusions", []), r["ruleId"])
                if r.get("enabledState") == "Disabled":
                    disabled.append(f"{rs['ruleSetType']}:{r['ruleId']}")
    settings = {
        "sku": (raw.get("sku") or {}).get("name"),
        "rulesets": [{"type": r["ruleSetType"], "version": r["ruleSetVersion"], "action": r.get("ruleSetAction")} for r in sets],
        "bot": any("BotManager" in r["ruleSetType"] for r in sets),
        "disabled_rules": sorted(set(disabled)),
        "exclusions": exclusions,
        "request_body_check": s.get("requestBodyCheck", "Enabled") == "Enabled",
        **_custom_rules(p.get("customRules", {}).get("rules", [])),
    }
    return WafPolicy(vendor="azure", name=raw["name"], native_id=_id(raw), mode=mode, settings=settings, raw=raw)


def normalize_legacy_waf(gw_name: str, gw_id: str, c: dict) -> WafPolicy:
    mode = MODE.get((c.get("firewallMode") or "").lower(), "unknown") if c.get("enabled") else "off"
    return WafPolicy(vendor="azure", name=f"{gw_name} (legacy WAF config)", native_id=f"{gw_id.lower()}#legacy", mode=mode, raw=c,
                     settings={"legacy": True, "rulesets": [{"type": c.get("ruleSetType"), "version": c.get("ruleSetVersion")}],
                               "bot": False, "request_body_check": c.get("requestBodyCheck", True),
                               "disabled_rules": [f"{d['ruleGroupName']}:{r}" for d in c.get("disabledRuleGroups", [])
                                                  for r in d.get("rules") or ["*"]],
                               "exclusions": _exclusions(c.get("exclusions", []))})
