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
