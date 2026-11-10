"""The fix plan: every finding rule has a remedy, issues are ranked by gain, and the score follows the checks."""
import re
from pathlib import Path

from waf_inventory import findings, remedies
from waf_inventory.models import Finding


def test_every_finding_rule_has_a_remedy():
    src = Path(findings.__file__).read_text()
    rules = set(re.findall(r'add\("([a-z0-9-]+)"', src)) | set(re.findall(r'rule="([a-z0-9-]+)"', src))
    assert rules and rules <= set(remedies.CHECKS)
    assert all(c[0] in remedies.WEIGHT and c[3] for c in remedies.CHECKS.values())


def test_plan_ranks_issues_and_shows_fixes_for_the_vendors_affected(session):
    p = remedies.plan(session)
    issues = {i["rule"]: i for i in p["issues"]}
    assert 0 < p["score"] < 100 and p["passed"] < p["checks"]
    assert [i["severity"] for i in p["issues"]][:4] == ["high"] * 4 and p["issues"][0]["gain"] > issues["exclusions"]["gain"]
    assert [v for v, _ in issues["detection-mode"]["fixes"]] == ["Azure", "F5 BIG-IP", "Baffin Bay"]
    assert [v for v, _ in issues["wildcard-urls"]["fixes"]] == ["F5 BIG-IP"]
    assert all(i["link"].startswith("/policy/") for i in issues["unused-policy"]["items"])
    assert any(i["link"] == "/apps/partners.contoso.com" for i in issues["no-waf"]["items"])


def test_fixing_an_issue_everywhere_raises_the_score(session):
    before = remedies.plan(session)
    top = before["issues"][0]
    session.query(Finding).filter_by(rule=top["rule"]).delete()
    after = remedies.plan(session)
    session.rollback()
    assert after["score"] - before["score"] in (top["gain"] - 1, top["gain"], top["gain"] + 1)  # rounding
    assert after["passed"] == before["passed"] + 1


def test_fix_plan_page_and_overview(client):
    page = client.get("/findings").text
    assert "Fix plan" in page and "You pass" in page and "How to fix" in page and 'href="/t/findings"' in page
    home = client.get("/").text
    assert "Posture score" in home and "Fix these first" in home and 'href="/findings#i1"' in home
    assert "across Azure, Baffin Bay, F5" in home


def test_application_verdict(client):
    assert "Protected: every route is behind a blocking WAF" in client.get("/apps/api.contoso.com").text
    shop = client.get("/apps/shop.contoso.com").text
    assert "Partly protected" in shop and "detect only (waf-agw-shop-api)" in shop
    assert "At risk" in client.get("/apps/partners.contoso.com").text


def test_search(client):
    page = client.get("/search", params={"q": "shop"}).text
    assert "Applications (1)" in page and 'href="/apps/shop.contoso.com"' in page and "WAF policies (" in page
    assert client.get("/search", params={"q": "partners.contoso"}, follow_redirects=False).status_code == 200  # a list
    jump = client.get("/search", params={"q": "Partners.Contoso.com"}, follow_redirects=False)  # a full name: its page
    assert jump.status_code == 303 and jump.headers["location"] == "/apps/partners.contoso.com"
    assert client.get("/search", params={"q": "waf-agw-unused"}, follow_redirects=False).headers["location"].startswith("/policy/")
    assert "Nothing matches" in client.get("/search", params={"q": "zzz-nothing"}).text


def test_finding_lifecycle_first_seen_accepted_and_resolved(tmp_path):
    from datetime import timedelta

    from waf_inventory import report
    from waf_inventory.cli import collect_source
    from waf_inventory.models import Finding, FindingState, connect, finding_key, utcnow

    examples = Path(__file__).resolve().parent.parent / "examples"
    s = connect(str(tmp_path / "t.db"))
    collect_source(s, {"_dir": examples}, {"type": "baffinbay_bundle", "name": "bb", "path": "baffinbay/bundle.json"})
    findings.run(s)
    f = s.query(Finding).filter_by(severity="high").first()
    st = s.get(FindingState, finding_key(f.rule, f.subject))
    assert st.status == "open" and st.first_seen and s.query(FindingState).count() == len({(x.rule, x.subject) for x in s.query(Finding)})
    seen, before = st.first_seen - timedelta(days=12), remedies.plan(s)
    st.first_seen = seen
    s.commit()

    findings.run(s)  # a recompute keeps the first-seen time
    item = next(i for issue in remedies.plan(s)["issues"] for i in issue["items"] if i["key"] == st.key)
    assert s.get(FindingState, st.key).first_seen == seen and item["age"] == 12

    for other in s.query(FindingState).filter_by(rule=f.rule):  # accept every finding of the rule: its check passes
        other.status, other.reason, other.expires = "accepted", "compensating control", utcnow() + timedelta(days=90)
    s.commit()
    after = remedies.plan(s)
    assert after["score"] > before["score"] and f.rule not in {i["rule"] for i in after["issues"]}
    assert st.key in {a["key"] for a in after["accepted"]}
    row = next(r for r in report.table(s, "findings") if (r["rule"], r["subject"]) == (f.rule, f.subject))
    assert row["status"] == "accepted" and row["accepted_reason"] == "compensating control" and row["age_days"] == 12
    assert report.summary(s)["findings"]["high"] == len(report.table(s, "findings", severity="high", status="open"))
    findings.run(s)
    assert s.get(FindingState, st.key).status == "accepted"  # survives a recompute

    s.get(FindingState, st.key).expires = utcnow() - timedelta(days=1)  # the acceptance ran out
    s.commit()
    assert f.rule in {i["rule"] for i in remedies.plan(s)["issues"]}
    findings.run(s)
    assert s.get(FindingState, st.key).status == "open"

    s.query(Finding).delete()  # nothing found any more: resolved, then back as a new occurrence
    findings._track(s, [])
    s.commit()
    st = s.get(FindingState, st.key)
    assert st.status == "resolved" and st.resolved and st.subject in {r["subject"] for r in remedies.plan(s)["resolved"]}
    findings.run(s)
    assert s.get(FindingState, st.key).status == "open" and s.get(FindingState, st.key).first_seen > seen


def test_accept_and_reopen_a_finding_in_the_console(client, session):
    from waf_inventory.models import AuditLog, FindingState

    page = client.get("/findings").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    key = re.search(r'name="key" value="(no-waf\|[^"]+)"', page)[1].replace("&amp;", "&")
    assert "Accept risk" in page and "accepted risk" not in page
    bad = client.post("/findings/decide", data={"csrf": csrf, "key": key, "decision": "accepted", "reason": " ", "days": "90"})
    assert bad.status_code == 400
    assert client.post("/findings/decide", data={"key": key, "decision": "accepted", "reason": "x", "days": "90"}).status_code == 403
    assert client.post("/findings/decide", data={"csrf": csrf, "key": "nope", "decision": "open"}).status_code == 404

    ok = client.post("/findings/decide", data={"csrf": csrf, "key": key, "decision": "accepted", "reason": "Internal only", "days": "30"})
    assert ok.status_code == 200 and "1 accepted risk" in ok.text and "Internal only" in ok.text and "Reopen" in ok.text
    session.expire_all()
    st = session.get(FindingState, key)
    assert st.status == "accepted" and st.user == "admin" and 29 <= (st.expires - st.decided).days <= 30
    assert session.query(AuditLog).filter_by(action="finding accepted", target=key).count() == 1
    assert "accepted" in client.get("/t/findings?status=accepted").text

    back = client.post("/findings/decide", data={"csrf": csrf, "key": key, "decision": "open"})
    assert back.status_code == 200 and "accepted risk" not in back.text
    session.expire_all()
    assert session.get(FindingState, key).status == "open" and session.get(FindingState, key).reason is None
