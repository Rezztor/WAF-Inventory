"""The Overview's protection score, map and fix-first queue."""
from waf_inventory import posture, report
from waf_inventory.models import get_setting, put_setting


def test_score_is_the_average_of_counted_application_points(session):
    v = posture.view(session)
    tiles = [t for g in v["map"] for t in g["tiles"]]
    assert v["web"] == sum(t["scored"] for t in tiles)
    assert 0 < v["score"] < 100
    assert v["counts"]["crit"] and v["counts"]["ok"]
    assert sum(v["counts"].values()) == len(tiles)


def test_points_fall_with_findings_and_never_below_zero():
    t = {"mode": "block", "found": [("old-ruleset", "medium"), ("unprotected-api", "high")]}
    assert posture._points(t) == 87
    assert posture._points(t, "old-ruleset") == 90
    assert posture._points({"mode": "detect", "found": [("x", "high")] * 9}) == 0


def test_fixing_a_no_waf_finding_counts_as_blocking():
    t = {"mode": "none", "found": [("no-waf", "high")]}
    assert posture._points(t) == 0
    assert posture._points(t, "no-waf") == 100


def test_queue_puts_the_biggest_gain_first_and_says_what_to_do(session):
    q = posture.view(session)["queue"]
    assert [g["gain"] for g in q] == sorted((g["gain"] for g in q), reverse=True)
    assert q[0]["gain"] > 0
    assert q[0]["fix"]
    assert all(g["link"].startswith(("/t/findings?", "/tuning")) for g in q)


def test_overview_shows_score_map_and_queue_without_a_script(client):
    html = client.get("/").text
    assert "Protection map" in html and "Fix first" in html and 'role="img" aria-label="Protection score' in html
    assert "<script" not in html


def test_empty_console_points_to_connections(console):
    html = console.get("/").text
    assert "No applications yet" in html and "Protection map" not in html


def test_trend_says_what_changed_since_the_day_before(session):
    saved = get_setting(session, "posture_history")
    try:
        put_setting(session, "posture_history", {"days": [
            {"day": "2026-10-01", "score": 30, "open": ["Gone\thost-a"]},
            {"day": "2026-10-02", "score": 20, "open": ["Gone\thost-a"]}]})
        posture.snapshot(session, "2026-10-03")
        days = get_setting(session, "posture_history")["days"]
        assert [("open" in d) for d in days] == [False, True, True]  # only the last two days keep their lists
        t = posture.view(session)["trend"]
        assert t["since"] == "2026-10-02" and t["delta"] == days[-1]["score"] - 20
        assert t["fixed"] == [["Gone", "host-a"]] and t["new"]
        assert len(t["line"].split()) == 3
        posture.snapshot(session, "2026-10-03")  # a second run on the same day replaces the day
        assert len(get_setting(session, "posture_history")["days"]) == 3
    finally:
        put_setting(session, "posture_history", saved)
        session.commit()


def test_no_trend_on_the_first_day(session):
    saved = get_setting(session, "posture_history")
    put_setting(session, "posture_history", {"days": [{"day": "2026-10-01", "score": 30}]})
    assert posture.view(session)["trend"] is None
    put_setting(session, "posture_history", saved)
    session.commit()


def test_search_finds_every_kind_of_thing_and_needs_every_word(session):
    names = {g["name"]: g for g in report.search(session, "contoso")}
    assert {"Applications", "Findings", "API endpoints"} <= set(names)
    assert report.search(session, "shop.contoso.com api")[0]["rows"]
    assert report.search(session, "no-such-thing-anywhere") == []


def test_search_page_escapes_input_and_opens_support_ids(client):
    html = client.get("/search", params={"q": "<script>alert(1)</script>"}).text
    assert "<script>alert" not in html and "Nothing matches" in html
    assert 'name="q"' in client.get("/").text
    assert "waf-agw-shop-api" in client.get("/search", params={"q": "waf-agw-shop-api"}).text
    r = client.get("/search", params={"q": "67f02707e74b581cabcf730b1a4b2284"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/tuning?support_id=67f02707e74b581cabcf730b1a4b2284"
