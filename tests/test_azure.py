import copy
import json
from types import SimpleNamespace

import httpx

from waf_inventory import azure, discovery
from conftest import EXAMPLES

BUNDLE = json.loads((EXAMPLES / "azure" / "bundle.json").read_text())


def parsed():
    gws, pols = azure.parse_bundle(copy.deepcopy(BUNDLE))
    listeners = {l.name: l for g in gws for l in g.listeners}
    return gws, {p.name: p for p in pols}, listeners


def test_appgw_effective_policy_per_listener_and_path():
    _, pols, ls = parsed()
    shop = ls["lst-shop-https"]
    assert shop.hostnames == ["shop.contoso.com"] and shop.port == 443 and shop.protocol == "https"
    assert shop.policy.name == "waf-agw-shop"  # per-site policy overrides the gateway policy
    routes = {r.name: r for r in shop.routes}
    assert routes["rr-shop/api"].paths == ["/api/*"] and routes["rr-shop/api"].policy.name == "waf-agw-shop-api"  # per-URI
    assert routes["rr-shop/admin"].policy.name == "waf-agw-shop"  # path rule without policy inherits the listener's
    assert routes["rr-shop/default"].backend == {"name": "pool-shop-web", "members": ["shop-web.internal.contoso.com"]}
    portal = ls["lst-portal-https"]
    assert portal.hostnames == ["portal.contoso.com", "reports.contoso.com"]
    assert portal.policy.name == "waf-agw-global"  # no listener policy -> gateway policy
    assert ls["lst-sftp-tcp"].waf_capable is False


def test_appgw_policy_normalization():
    _, pols, _ = parsed()
    g = pols["waf-agw-global"]
    assert g.mode == "block" and g.settings["bot"] is True
    assert g.settings["rulesets"][0] == {"type": "OWASP", "version": "3.2"}
    assert g.settings["disabled_rules"] == ["OWASP:942100"]
    assert g.settings["exclusions"][0]["selector"] == "x-api-token"
    assert any("GeoMatch KP, IR, SY" in c for r in g.settings["custom_rules"] for c in r["conditions"])
    assert "Allow: 203.0.113.0/24" in g.settings["ip_lists"]
    api = pols["waf-agw-shop-api"]
    assert api.mode == "detect" and api.settings["request_body_check"] is False
    assert pols["waf-agw-shop"].settings["rate_limits"][0]["threshold"] == 100
    legacy = pols["agw-dev (legacy WAF config)"]
    assert legacy.mode == "detect" and legacy.settings["legacy"] and len(legacy.settings["disabled_rules"]) == 2
    assert all(len(p.raw_hash) == 64 for p in pols.values())


def test_front_door_domains_follow_security_policies():
    _, pols, ls = parsed()
    assert ls["api-contoso-com"].policy.name == "fdwafcontoso"
    assert ls["partners-contoso-com"].policy is None  # domain without a security policy
    assert ls["ep-contoso"].hostnames == ["ep-contoso-b4c3d2e1f0.z01.azurefd.net"]
    assert [r.name for r in ls["ep-contoso"].routes] == ["route-www"]  # linkToDefaultDomain
    assert ls["api-contoso-com"].routes[0].backend["members"] == ["apim-contoso.azure-api.net"]
    fd = pols["fdwafcontoso"]
    assert fd.mode == "block" and fd.settings["bot"] and fd.settings["disabled_rules"] == ["Microsoft_DefaultRuleSet:942440"]
    assert fd.settings["rate_limits"][0]["threshold"] == 600


def test_unreadable_policy_becomes_placeholder():
    b = copy.deepcopy(BUNDLE)
    b["appgw_policies"] = [p for p in b["appgw_policies"] if p["name"] != "waf-agw-shop"]
    gws, pols = azure.parse_bundle(b)
    ph = next(p for p in pols if p.name == "waf-agw-shop")
    assert ph.mode == "unknown" and "not readable" in ph.settings["note"]


def test_az_cli_flattened_shape_parses():
    flat = copy.deepcopy(BUNDLE["appgws"][0])
    flat.update(flat.pop("properties"))
    g = azure.parse_appgw(flat, {})
    assert {l.name for l in g.listeners} >= {"lst-shop-https", "lst-sftp-tcp"}


class FakeCred:
    def get_token(self, scope):
        return SimpleNamespace(token="t-" + scope)


def arm_mock():
    """Serve the example bundle the way ARM does: separate calls per resource, paging, one 429."""
    b = copy.deepcopy(BUNDLE)
    sub = "/subscriptions/00000000-1111-2222-3333-444444444444"
    afd = b["afd_profiles"][0]
    pid = afd["profile"]["id"]
    groups = [{k: v for k, v in g.items() if k != "origins"} for g in afd["originGroups"]]
    routes = {
        "/subscriptions": [{"subscriptionId": sub.rsplit("/", 1)[1]}],
        f"{sub}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies": b["appgw_policies"],
        f"{sub}/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies": b["afd_policies"],
        f"{sub}/providers/Microsoft.Cdn/profiles": [afd["profile"], {"id": "/x/classic", "name": "classic", "sku": {"name": "Standard_Microsoft"}}],
        f"{pid}/afdEndpoints": afd["endpoints"], f"{pid}/customDomains": afd["customDomains"],
        f"{pid}/originGroups": groups, f"{pid}/securityPolicies": afd["securityPolicies"],
        f"{afd['endpoints'][0]['id']}/routes": afd["routes"],
        **{f"{g['id']}/origins": g["origins"] for g in afd["originGroups"]},
    }
    seen = {"throttled": False, "auth": set()}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"].add(req.headers["Authorization"])
        if req.url.host == "api.loganalytics.io":
            body = json.loads(req.content)
            assert body["timespan"] == "P7D" and "AGWAccessLogs" in body["query"]
            cols = ["Host", "Method", "Path", "QueryNames", "Status", "ContentType", "Hits", "FirstSeen", "LastSeen", "UserAgent"]
            rows = [["shop.contoso.com", "GET", f"/api/v1/products/{i}", "fields", 200, "application/json", 3,
                     "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "okhttp"] for i in range(12)]
            return httpx.Response(200, json={"tables": [{"name": "PrimaryResult", "columns": [{"name": c} for c in cols], "rows": rows}]})
        path = req.url.path
        if not seen["throttled"]:
            seen["throttled"] = True
            return httpx.Response(429, headers={"Retry-After": "0"})
        if path.endswith("/applicationGateways"):  # two pages
            if "page=2" in str(req.url):
                return httpx.Response(200, json={"value": [b["appgws"][1]]})
            return httpx.Response(200, json={"value": [b["appgws"][0]], "nextLink": f"https://management.azure.com{path}?api-version=x&page=2"})
        assert req.url.params["api-version"]
        return httpx.Response(200, json={"value": routes[path]})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_live_fetch_matches_bundle_and_logs_feed_discovery():
    http, seen = arm_mock()
    arm = azure.Arm(FakeCred(), http)
    assert azure.fetch_bundle(arm) == BUNDLE
    assert seen["throttled"]
    assert {"Bearer t-https://management.azure.com/.default", "Bearer t-https://api.loganalytics.io/.default"} >= seen["auth"]
    obs = list(azure.fetch_observations(arm, ["ws1"], days=7))
    assert len(obs) == 12 and obs[0]["path"] == "/api/v1/products/0?fields=" and obs[0]["hits"] == 3
    eps = discovery.discover(obs)
    assert [(e["template"], e["hits"], e["query_params"]) for e in eps] == [("/api/v1/products/{product_id}", 36, ["fields"])]
    assert len(seen["auth"]) == 2
