"""Baffin Bay: inventory from traffic configurations, stored WAF events, and the false-positive tuning plan."""
import json
from datetime import datetime, timedelta, timezone

import httpx

from conftest import EXAMPLES, add, csrf, wait
from waf_inventory import baffinbay, report, tuning
from waf_inventory.cli import store_events
from waf_inventory.models import WafEvent, connect

BUNDLE = json.loads((EXAMPLES / "baffinbay" / "bundle.json").read_text())


def test_proxies_become_gateways_listeners_and_policies():
    gws, pols = baffinbay.build(BUNDLE)
    by = {g.name: g for g in gws}
    portal = by["contoso-portal"].listeners[0]
    assert (portal.protocol, portal.port, portal.hostnames) == ("https", 443, ["portal.contoso.com", "api.contoso.com"])
    assert [r.name for r in portal.routes] == ["legacy-api", "default"]  # traffic rules first, the proxy's backend last
    assert portal.routes[0].paths == ["/legacy/*"] and portal.routes[0].hosts == ["api.contoso.com"]
    assert by["contoso-sftp"].listeners[0].waf_capable is False
    p = {x.name: x for x in pols}
    assert (p["contoso-portal"].mode, p["contoso-blog"].mode) == ("block", "detect")
    st = p["contoso-portal"].settings
    assert st["rulesets"] == [{"type": "CRS", "version": "4.22.0", "requested": "4.*.*"}]
    assert st["disabled_rules"] == ["path /{*}/upload: all rules"]
    assert st["backend_tls"] == "not verified" and st["hsts"] is True and st["matched_data"] is True
    assert st["rate_limits"] == [{"name": "per source IP", "rate": "100 r/s", "burst": 10}]
    assert st["staged_waf"] == {"mode": "PARANOIA_LEVEL", "paranoia_level": 3, "crs": None, "exclusions": 1}
    blog = p["contoso-blog"].settings
    assert (blog["backend_tls"], blog["hsts"], blog["rate_limits"], blog["body_parsing_off"]) == ("plaintext", None, [], ["/xmlrpc.php"])


def test_stored_events_keep_only_host_and_user_agent_from_the_headers():
    row = baffinbay.event_row(BUNDLE["events"][0])
    assert row["host"] == "api.contoso.com" and row["user_agent"].startswith("Mozilla/5.0")
    assert "secret" not in json.dumps(row)  # the Cookie header is never stored
    assert row["rules"] == [{"id": "942100", "name": "SQL Injection Attack Detected via libinjection"}]


def test_events_are_stored_once_and_aged_out_after_35_days(tmp_path):
    s = connect(str(tmp_path / "t.db"))
    old = json.loads(json.dumps(BUNDLE["events"][0]))
    old["id"], old["attributes"]["timestamp"] = "old-one", "2026-08-01T00:00:00.000Z"
    store_events(s, "bb", "baffinbay", BUNDLE["events"] + [old])
    assert s.query(WafEvent).count() == len(BUNDLE["events"])  # 2 months before the newest: dropped at once
    assert store_events(s, "bb", "baffinbay", BUNDLE["events"]) == 0


def test_findings_for_proxy_settings(session):
    got = {(f["rule"], f["subject"]) for f in report.table(session, "findings")}
    assert {("detection-mode", "baffinbay: contoso-blog"), ("no-rate-limit", "baffinbay: contoso-blog"),
            ("risky-methods", "baffinbay: contoso-blog"), ("body-inspection-off", "baffinbay: contoso-blog"),
            ("matched-data-off", "baffinbay: contoso-blog"), ("no-bot-protection", "baffinbay: contoso-blog"),
            ("backend-tls-unverified", "baffinbay: contoso-portal"), ("wide-exclusion", "baffinbay: contoso-portal"),
            ("disabled-rules", "baffinbay: contoso-portal"), ("tuning-candidates", "baffinbay: contoso-portal")} <= got
    assert ("no-hsts", "baffinbay: contoso-blog") not in got  # plain HTTP: HSTS does not apply


def test_tuning_tells_false_positives_from_attacks(session):
    rows = {(g["rule"], g["path"]): g for g in tuning.groups(session)}
    fp = rows[("942100", "/api/v1/orders/{order_id}/notes")]
    assert fp["verdict"] == "false positive" and fp["score"] >= tuning.LIKELY
    assert fp["proposal"] == {"match": "/api/v1/orders/{*}/notes", "rule": "942100"}
    assert any("answered 100%" in x for x in fp["evidence"])  # the staged copies reached the application and got 201
    probe = rows[("930130", "/.env")]
    assert probe["verdict"] == "attack" and probe["proposal"] is None and "scanner" in probe["attack_signs"][0]
    assert rows[("920420", "/api/v1/partner/feed")]["verdict"] == "unsure"  # one partner, four events: a person decides
    assert rows[("941100", "/comments")]["verdict"] == "unsure"


def test_no_proposal_that_would_cover_the_whole_site(session):
    g = tuning._score(("p", "942100", "POST", "/{param}/notes"),
                      [WafEvent(id=str(i), time=f"2026-10-2{i % 6}T10:00:00Z", host="a.com", path="/x/notes", status=200, action="LOGGED",
                                rules=[{"id": "942100", "name": ""}], source_ip=f"192.0.2.{i}", user_agent="Mozilla/5.0", matched=[])
                       for i in range(20)], None, {})
    assert g["verdict"] == "false positive" and g["proposal"] is None and "whole site" in g["note"]


def test_live_sign_in_is_reused_and_events_are_paged():
    calls = []
    first = {"data": BUNDLE["events"][:2], "links": {"next": "/api/v2/insight/http-security-events?page%5Bafter%5D=abc&page%5Bsize%5D=100"}}

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.url.host, req.url.path, dict(req.url.params)))
        if req.url.host == "m2m-auth.baffinbay.com":
            assert json.loads(req.content)["audience"] == "https://portal.baffinbay.com"
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 86400})
        assert req.headers["Authorization"] == "Bearer tok"
        if req.url.path.endswith("traffic-configs"):
            return httpx.Response(200, json=BUNDLE["traffic_configs"])
        if "core-rule-sets" in req.url.path:
            return httpx.Response(200, json={"data": {"attributes": {"rules": [{"modSecId": "942100", "id": "u-942100"}]}}})
        if req.url.params.get("page[after]") == "gone":
            return httpx.Response(400, json={"errors": []})
        return httpx.Response(200, json=first if "page[after]" not in req.url.params else {"data": BUNDLE["events"][2:3], "links": {}})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    c = baffinbay.Client("id", "secret", http=http)
    b = baffinbay.fetch(c, "tenant-1", after="gone")  # an aged-out cursor starts again from the oldest event
    assert len(b["events"]) == 3 and b["core_rule_sets"]["crs-v4.22.0"] == {"942100": "u-942100"}
    assert calls[-1][2]["page[after]"] == "abc" and calls[-1][2]["filter[tenantId]"] == "tenant-1"
    assert sum(h == "m2m-auth.baffinbay.com" for h, _, _ in calls) == 1
    again = baffinbay.Client("id", "secret", token=c.token, http=http)  # the next run reuses the stored token
    again.get("/api/v2/traffic-mgmt/traffic-configs")
    assert sum(h == "m2m-auth.baffinbay.com" for h, _, _ in calls) == 1
    stale = {"access_token": "tok", "expires": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}
    baffinbay.Client("id", "secret", token=stale, http=http).get("/api/v2/traffic-mgmt/traffic-configs")
    assert sum(h == "m2m-auth.baffinbay.com" for h, _, _ in calls) == 2  # less than an hour left: a new one


def test_tuning_page_decisions_and_change_files(console):
    c = console
    sid = add(c, "baffinbay_bundle", name="bb", path=str(c.dir / "baffinbay" / "bundle.json"), schedule_every="off")
    wait(c, c.post(f"/sources/{sid}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"])
    page = c.get("/tuning").text
    assert "Likely false positives (1)" in page and "/api/v1/orders/{*}/notes" in page
    key = page.split('name="key" value="')[1].split('"')[0]
    assert c.post("/tuning/decide", data={"csrf": csrf(c, "/tuning"), "key": key, "decision": "approved", "back": "/tuning"},
                  follow_redirects=False).status_code == 303
    body = json.loads(c.get("/export/tuning-approved.json").text)
    assert [x["proxy"] for x in body] == ["contoso-portal"] and body[0]["unknown_rule_ids"] == []
    staged = body[0]["1_stage"]["data"]["attributes"]["waf"]["stagedWaf"]
    assert staged["state"] == "ENABLED" and staged["paranoiaLevel"] == 3  # the staged WAF's own settings are kept
    assert [e["match"] for e in staged["pathExclusions"]] == ["/api/v1/search", "/api/v1/orders/{*}/notes"]  # existing ones stay
    active = body[0]["2_promote"]["data"]["attributes"]["waf"]["pathExclusions"]
    assert [e["match"] for e in active] == ["/api/v1/search", "/{*}/upload", "/api/v1/orders/{*}/notes"]
    assert '"/api/v1/orders/{*}/notes"' in c.get("/export/tuning-approved.tf").text
    hit = BUNDLE["events"][0]["attributes"]["supportId"]
    found = c.get(f"/tuning?support_id={hit}").text
    assert "Found: blocked" in found and "approved by admin" in found
    assert "No stored event" in c.get("/tuning?support_id=nope").text
    assert "tuning approved" in c.get("/audit").text
