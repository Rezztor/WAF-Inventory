import json
import re
import time
from datetime import datetime, timezone

import httpx
import pytest

from waf_inventory import f5, findings
from waf_inventory.models import connect, save_snapshot
from conftest import EXAMPLES


def offline():
    gws, pols = f5.build(f5.load_offline(EXAMPLES / "f5"))
    return gws[0], {p.name: p for p in pols}, {l.name: l for l in gws[0].listeners}


def test_offline_device_and_virtual_servers():
    gw, pols, ls = offline()
    assert gw.name == "dc1-bigip01.corp.contoso.com" and gw.version == "17.1.1"
    app1 = ls["/Common/vs_app1_https"]
    assert (app1.address, app1.port, app1.protocol) == ("10.10.20.10", 443, "https")
    assert app1.hostnames == ["app1.corp.contoso.com"]  # client-ssl server-name
    assert app1.policy.name == "/Common/app1_waf"  # LTM policy rule without conditions = default
    api = next(r for r in app1.routes if r.name.endswith(":api_path"))
    assert api.paths == ["/api/*"] and api.policy.name == "/Common/app1_api_waf"
    assert api.backend == {"name": "/Common/pool_app1_api", "members": ["/Common/10.10.31.21:8443"]}
    partner = ls["/Partner/vs_partner_api"]
    assert partner.address == "10.30.0.10%2"  # route domain kept
    assert partner.policy.name == "/Partner/partner_api_waf"
    assert ls["/Common/vs_ssh_fwd"].waf_capable is False and ls["/Common/vs_ssh_fwd"].protocol == "tcp"
    assert ls["/Common/vs_legacy_http"].policy is None


def test_host_based_ltm_policy_and_asm_disable():
    _, _, ls = offline()
    hr = ls["/Common/vs_hr_https"]
    assert hr.hostnames == ["hr.corp.contoso.com", "selfservice.corp.contoso.com"]
    assert hr.policy is None  # no catch-all rule
    routes = {r.name.split(":")[-1]: r for r in hr.routes}
    assert routes["selfservice"].hosts == ["selfservice.corp.contoso.com"]
    assert routes["selfservice"].backend["name"] == "/Common/pool_selfservice"
    assert routes["healthcheck"].paths == ["/healthz"] and routes["healthcheck"].policy is None  # asm disable


def test_irule_asm_enable():
    _, _, ls = offline()
    assert ls["/Common/vs_intranet_http"].policy.name == "/Common/intranet_waf"


def test_asm_policy_normalization():
    _, pols, _ = offline()
    api = pols["/Common/app1_api_waf"]
    assert api.mode == "block" and api.settings["export"] == "declarative"
    assert {"name": "/api/v1/employees/*", "method": "*", "type": "wildcard", "protocol": "https"} in api.settings["allowed_urls"]
    assert api.settings["ip_lists"] == ["10.0.0.0/255.0.0.0"] and api.settings["geo"] == ["North Korea", "Iran"]
    assert api.settings["openapi_files"] == ["https://git.corp.contoso.com/specs/app1-api/openapi.yaml"]
    assert api.settings["data_guard"] is True and api.settings["brute_force"] is True
    app1 = pols["/Common/app1_waf"]
    assert app1.settings["signature_staging"] is True and app1.settings["staged_signatures"] == 1
    assert app1.settings["disabled_rules"] == ["200101609"] and app1.settings["violations_not_blocking"] == ["VIOL_EVASION"]
    assert pols["/Common/hr_waf"].mode == "detect"
    assert pols["/Common/old_unused_waf"].mode == "off"  # not active
    assert pols["/Partner/partner_api_waf"].settings["export"] == "missing"


def test_tmsh_relative_names_and_quotes(tmp_path):
    text = """
ltm virtual vs_rel {
    destination 10.1.1.1:80
    pool p_rel
    profiles {
        http { }
    }
    description "has { braces } and spaces"
}
ltm pool p_rel {
    members {
        10.2.2.2:80 {
            address 10.2.2.2
        }
    }
}
ltm virtual Tenant/vs_v6 {
    destination Tenant/2001:db8::10.443
    profiles {
        /Common/http { }
    }
}
"""
    o = f5.parse_conf(text)["objs"]
    assert set(o["ltm virtual"]) == {"/Common/vs_rel", "/Tenant/vs_v6"}
    assert o["ltm virtual"]["/Common/vs_rel"]["description"] == "has { braces } and spaces"
    (tmp_path / "tmsh.txt").write_text(text)
    gws, _ = f5.build(f5.load_offline(tmp_path))
    ls = {l.name: l for l in gws[0].listeners}
    assert ls["/Common/vs_rel"].routes[0].backend == {"name": "/Common/p_rel", "members": ["/Common/10.2.2.2:80"]}
    assert (ls["/Tenant/vs_v6"].address, ls["/Tenant/vs_v6"].port, ls["/Tenant/vs_v6"].protocol) == ("2001:db8::10", 443, "http")


# ---------------------------------------------------------------- live REST against a mock BIG-IP

ASM_FILE = (EXAMPLES / "f5" / "asm" / "app1_waf.json").read_bytes()
IRULE = re.search(r"ltm rule /Common/irule_asm_intranet \{\n(.*?)\n\}\n", (EXAMPLES / "f5" / "bigip.conf").read_text(), re.S).group(1)
NOW = time.time()
NEAR = int((NOW + 10 * 86400) * 1000)  # sys/file/ssl-cert expirationDate: epoch milliseconds
FAR = int((NOW + 400 * 86400) * 1000)
NEAR_TEXT = datetime.fromtimestamp(NEAR / 1000, tz=timezone.utc).strftime("%b %d %H:%M:%S %Y GMT")
REST = {
    "/mgmt/tm/sys/global-settings": {"hostname": "dc1-bigip01.corp.contoso.com"},
    "/mgmt/tm/sys/version": {"entries": {"https://localhost/mgmt/tm/sys/version/0": {"nestedStats": {"entries": {
        "Build": {"description": "0.0.4"}, "Version": {"description": "17.1.1"}}}}}},
    "/mgmt/tm/sys/provision": {"items": [{"name": "ltm", "level": "nominal"}, {"name": "asm", "level": "nominal"}]},
    "/mgmt/tm/ltm/virtual": {"items": [
        {"name": "vs_app1_https", "fullPath": "/Common/vs_app1_https", "destination": "/Common/10.10.20.10:443",
         "pool": "/Common/pool_app1", "rules": [],
         "profilesReference": {"items": [{"fullPath": p} for p in ("/Common/clientssl-app1", "/Common/http-xff", "/Common/serverssl",
                                                                   "/Common/tcp", "/Common/websecurity")]},
         "policiesReference": {"items": [{"fullPath": "/Common/asm_app1"}]}},
        {"name": "vs_intranet_http", "fullPath": "/Common/vs_intranet_http", "destination": "/Common/10.10.20.12:80",
         "pool": "/Common/pool_intranet", "rules": ["/Common/irule_asm_intranet"],
         "profilesReference": {"items": [{"fullPath": p} for p in ("/Common/http", "/Common/tcp", "/Common/websecurity")]}},
    ]},
    "/mgmt/tm/ltm/pool": {"items": [
        {"fullPath": "/Common/pool_app1", "membersReference": {"items": [{"fullPath": "/Common/10.10.30.11:8080"}, {"fullPath": "/Common/10.10.30.12:8080"}]}},
        {"fullPath": "/Common/pool_app1_api", "membersReference": {"items": [{"fullPath": "/Common/10.10.31.21:8443"}]}},
        {"fullPath": "/Common/pool_intranet", "membersReference": {"items": [{"fullPath": "/Common/10.10.33.10:80"}]}}]},
    "/mgmt/tm/ltm/policy": {"items": [
        {"fullPath": "/Common/asm_app1", "rulesReference": {"items": [
            {"name": "api_path",
             "conditionsReference": {"items": [{"name": "0", "httpUri": True, "path": True, "startsWith": True, "values": ["/api/"]}]},
             "actionsReference": {"items": [{"name": "0", "asm": True, "enable": True, "policy": "/Common/app1_api_waf"},
                                            {"name": "1", "forward": True, "select": True, "pool": "/Common/pool_app1_api"}]}},
            {"name": "default", "actionsReference": {"items": [{"name": "0", "asm": True, "enable": True, "policy": "/Common/app1_waf"}]}}]}},
        {"fullPath": "/Common/Drafts/asm_app1_new", "status": "draft"}]},
    "/mgmt/tm/ltm/rule": {"items": [{"fullPath": "/Common/irule_asm_intranet", "apiAnonymous": IRULE}]},
    "/mgmt/tm/ltm/profile/client-ssl": {"items": [
        {"fullPath": "/Common/clientssl-app1", "serverName": "app1.corp.contoso.com", "ciphers": "DEFAULT:+RC4-SHA",
         "options": ["dont-insert-empty-fragments"], "allowNonSsl": "enabled", "renegotiation": "enable",
         "certKeyChain": [{"name": "app1_cert", "cert": "/Common/app1.corp.contoso.com.crt",
                           "key": "/Common/app1.corp.contoso.com.key"}]}]},
    "/mgmt/tm/ltm/profile/http": {"items": [{"fullPath": "/Common/http"}, {"fullPath": "/Common/http-xff"}]},
    "/mgmt/tm/asm/policies": {"items": [
        {"id": "A1", "name": "app1_waf", "fullPath": "/Common/app1_waf", "enforcementMode": "blocking", "active": True,
         "virtualServers": ["/Common/vs_app1_https"], "type": "security"},
        {"id": "A2", "name": "app1_api_waf", "fullPath": "/Common/app1_api_waf", "enforcementMode": "blocking", "active": True,
         "virtualServers": ["/Common/vs_app1_https"], "type": "security"}],
        "nextLink": "https://localhost/mgmt/tm/asm/policies?$skip=2"},
    "/mgmt/tm/asm/policies/A2/urls": {"items": [{"name": "/api/v1/employees", "method": "GET", "type": "explicit", "protocol": "https"}]},
    "/mgmt/tm/asm/policies/A2/methods": {"items": [{"name": "GET"}]},
    "/mgmt/tm/asm/policies/A2/whitelist-ips": {"items": [{"ipAddress": "10.0.0.0", "ipMask": "255.0.0.0"}]},
    "/mgmt/tm/asm/policies/A2/signature-sets": {"items": [{"signatureSetReference": {"link": "https://localhost/mgmt/tm/asm/signature-sets/High%20Accuracy?ver=17"}, "block": True, "alarm": True}]},
    "/mgmt/tm/asm/policies/A2/blocking-settings/violations": {"items": [{"description": "Illegal URL", "block": False, "alarm": True}]},
    "/mgmt/tm/sys/failover": {"apiRawValues": {"apiAnonymous": "Failover active for 2d 03:22:15\n"}},
    "/mgmt/tm/sys/file/ssl-cert": {"items": [
        {"fullPath": "/Common/app1.corp.contoso.com.crt", "expirationDate": NEAR, "expirationString": NEAR_TEXT,
         "issuer": "CN=Contoso Internal CA", "keyType": "rsa-private", "certificateKeySize": 2048, "fingerprint": "AA:BB"},
        {"fullPath": "/Common/legacy.corp.crt", "expirationDate": FAR, "expirationString": "Dec  1 12:00:00 2027 GMT",
         "issuer": "CN=Contoso Internal CA", "keyType": "ec-private", "certificateKeySize": 256, "fingerprint": "CC:DD"}]},
}
PAGE2 = {"items": [{"id": "A3", "name": "intranet_waf", "fullPath": "/Common/intranet_waf", "enforcementMode": "blocking",
                    "active": True, "virtualServers": [], "type": "security"},
                   {"id": "P", "name": "parent", "fullPath": "/Common/parent", "type": "parent"}]}


def bigip(monkeypatch):
    monkeypatch.setattr(f5, "CHUNK", 400)  # force several Content-Range chunks
    monkeypatch.setattr(f5.time, "sleep", lambda s: None)
    files = {"A1": ASM_FILE, "A3": (EXAMPLES / "f5" / "asm" / "intranet_waf.json").read_bytes()}
    log = {"calls": [], "polls": 0, "busy": True}

    def handler(req: httpx.Request) -> httpx.Response:
        p, m = req.url.path, req.method
        log["calls"].append((m, p))
        if p == "/mgmt/shared/authn/login":
            assert json.loads(req.content)["loginProviderName"] == "tmos"
            return httpx.Response(200, json={"token": {"token": "TKN"}})
        assert req.headers["X-F5-Auth-Token"] == "TKN"
        if m == "PATCH":  # the client asks for a longer token life right after sign-in
            log["patched"] = json.loads(req.content)
            return httpx.Response(200, json={"timeout": 3600})
        if m == "DELETE":
            return httpx.Response(200, json={})
        if log.get("failover") and p == "/mgmt/tm/sys/failover":
            return httpx.Response(200, json={"apiRawValues": {"apiAnonymous": log["failover"]}})
        if log.get("expired") and not log.get("relogged"):  # the token died mid-run
            log["relogged"] = True
            return httpx.Response(401, json={"message": "F5 OAuth token timeout"})
        if p == "/mgmt/tm/ltm/virtual" and log["busy"]:  # restjavad overloaded once
            log["busy"] = False
            return httpx.Response(503)
        if p == "/mgmt/tm/asm/tasks/export-policy" and m == "POST":
            pid = json.loads(req.content)["policyReference"]["link"].rsplit("/", 1)[1]
            if pid == "A2":
                return httpx.Response(403, json={"message": "Forbidden"})
            return httpx.Response(200, json={"id": "T" + pid})
        if p.startswith("/mgmt/tm/asm/tasks/export-policy/"):
            log["polls"] += 1
            return httpx.Response(200, json={"status": "COMPLETED" if log["polls"] % 2 == 0 else "STARTED"})
        if p.startswith("/mgmt/tm/asm/file-transfer/downloads/"):
            data = files["A1" if "A1" in p else "A3"]
            start, end = map(int, req.headers["Content-Range"].split("/")[0].split("-"))
            chunk = data[start:end + 1]
            return httpx.Response(200, content=chunk, headers={"Content-Range": f"{start}-{start + len(chunk) - 1}/{len(data)}"})
        if p == "/mgmt/tm/asm/policies" and req.url.params.get("$skip") == "2":
            return httpx.Response(200, json=PAGE2)
        if p in REST:
            return httpx.Response(200, json=REST[p])
        return httpx.Response(404, json={"message": "not found"})

    c = f5.F5Client("bigip", "auditor", "secret", http=httpx.Client(base_url="https://bigip", transport=httpx.MockTransport(handler)))
    return c, log


def test_rest_fetch_matches_offline(monkeypatch):
    c, log = bigip(monkeypatch)
    c.login()
    cfg, warnings = f5.fetch_rest(c)
    c.logout()
    assert ("DELETE", "/mgmt/shared/authz/tokens/TKN") in log["calls"]
    assert len(warnings) == 1 and "app1_api_waf" in warnings[0]  # 403 on export -> subcollections
    assert "/Common/parent" not in cfg["asm"] and "/Common/Drafts/asm_app1_new" not in cfg["ltm_policies"]
    assert cfg["asm"]["/Common/app1_waf"]["export"] == json.loads(ASM_FILE)  # reassembled from ~10 chunks
    assert sum(1 for m, p in log["calls"] if "downloads" in p) > 5

    gws, pols = f5.build(cfg)
    rest = {l.name: l for l in gws[0].listeners}
    _, _, off = offline()

    def shape(l):
        return (l.protocol, l.port, l.hostnames, l.policy and l.policy.name, l.policy and l.policy.mode,
                [(r.name, r.paths, r.policy and r.policy.name, r.backend) for r in l.routes])

    for name in ("/Common/vs_app1_https", "/Common/vs_intranet_http"):
        assert shape(rest[name]) == shape(off[name])
    api = next(p for p in pols if p.name == "/Common/app1_api_waf")
    assert api.settings["export"] == "rest-subcollections"
    assert api.settings["allowed_urls"][0]["name"] == "/api/v1/employees"
    assert api.settings["signature_sets"][0]["name"] == "High%20Accuracy"
    assert api.settings["violations_not_blocking"] == ["Illegal URL"]
    assert gws[0].version == "17.1.1 0.0.4"


def test_truncated_export_fails_loudly(monkeypatch):
    c, _ = bigip(monkeypatch)
    real = c.http.request

    def cut(method, url, **kw):
        r = real(method, url, **kw)
        if "downloads" in str(url):
            return httpx.Response(200, content=r.content[:10], headers={"Content-Range": "0-9/10"}, request=r.request)
        return r

    monkeypatch.setattr(c.http, "request", cut)
    c.login()
    with pytest.raises(json.JSONDecodeError):
        c.export_policy("A1")


def test_token_life_extended_and_reissued_on_expiry(monkeypatch):
    c, log = bigip(monkeypatch)
    log["expired"] = True  # the first authenticated request is refused: the token died
    c.login()
    assert log["patched"] == {"timeout": 3600}  # the default 20-minute life was extended (F5 K43590271)
    cfg, _ = f5.fetch_rest(c)
    assert sum(1 for m, p in log["calls"] if p == "/mgmt/shared/authn/login") == 2  # signed in again mid-run
    assert cfg["device"]["failover"] == "active"


def test_standby_unit_is_reported(monkeypatch):
    c, log = bigip(monkeypatch)
    log["failover"] = "Failover standby for 0d 04:35:49\n"
    c.login()
    cfg, warnings = f5.fetch_rest(c)
    assert cfg["device"]["failover"] == "standby"
    assert any("standby" in w for w in warnings)


def test_certificate_expiry_and_expiry_parsing():
    iso = f5.expiry_iso(int((time.time() + 10.5 * 86400) * 1000), NEAR_TEXT)  # fresh, or the seconds since module load shave a day off
    assert iso and (datetime.fromisoformat(iso) - datetime.now(timezone.utc)).days == 10
    secs = f5.expiry_iso(int(NOW + 10 * 86400), "x")
    assert secs and secs.startswith("20")  # seconds, not milliseconds
    text = f5.expiry_iso(None, "Dec  1 12:00:00 2027 GMT")
    assert text and text.startswith("2027-12-01")
    assert f5.expiry_iso(None, None) is None


def test_rest_tls_posture_and_certificate_findings(monkeypatch, tmp_path):
    c, _ = bigip(monkeypatch)
    c.login()
    cfg, _ = f5.fetch_rest(c)
    gws, pols = f5.build(cfg)
    lst = {l.name: l for l in gws[0].listeners}["/Common/vs_app1_https"]
    assert lst.tls["ciphers"] == "DEFAULT:+RC4-SHA" and lst.tls["allow_non_ssl"] is True
    assert "/Common/app1.corp.contoso.com.crt" in lst.tls["certs"]
    assert lst.tls["certs"]["/Common/app1.corp.contoso.com.crt"]["key_size"] == 2048

    s = connect(str(tmp_path / "t.db"))
    save_snapshot(s, "dc1-bigip01", "f5", gws, pols)
    got = {(x.rule, x.severity) for x in findings.run(s)}
    s.close()
    assert ("weak-ciphers", "medium") in got            # +RC4-SHA in the client-ssl profile
    assert ("non-ssl-allowed", "medium") in got         # allowNonSsl enabled
    assert ("expiring-certificate", "high") in got       # 10 days out


def test_offline_tls_facts_from_conf():
    _, _, ls = offline()
    partner = ls["/Partner/vs_partner_api"]
    assert partner.tls["ciphers"] == "DEFAULT:+RC4-SHA" and partner.tls["allow_non_ssl"] is True
    assert partner.tls["certs"] == {}  # the cert file itself is not in the conf: expiry needs the live path
    app1 = ls["/Common/vs_app1_https"]
    assert app1.tls["ciphers"] == "" and app1.tls["allow_non_ssl"] is False


def test_weak_cipher_rule_parsing():
    assert findings._weak_ciphers("DEFAULT:-SSLv3:-TLSv1:+RC4-SHA:DES-CBC3-SHA:AES128-SHA256") == ["+RC4-SHA", "DES-CBC3-SHA"]
    assert findings._weak_ciphers("DEFAULT:+RC4") == ["+RC4"]
    assert findings._weak_ciphers("DEFAULT:ECDHE-RSA-AES128-GCM-SHA256") == []
    assert findings._weak_ciphers("DEFAULT:TLSv1_2") == []  # TLS 1.2 is fine
    assert findings._weak_ciphers("DEFAULT:TLSv1_1") == ["TLSv1_1"]
    assert findings._weak_ciphers(None) == []
