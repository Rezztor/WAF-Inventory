"""The Overview's protection score, map and fix-first queue."""
from waf_inventory import posture


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
