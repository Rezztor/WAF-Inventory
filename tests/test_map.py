"""The Overview's protection map."""
from waf_inventory import report


def test_every_application_appears_once_with_the_verdict_of_its_own_page(session, client):
    m = report.protection_map(session)
    tiles = [t for g in m["gateways"] for t in g["tiles"]]
    assert len({t["host"] for t in tiles}) == len(tiles) == m["total"] == len({a["application"] for a in report.table(session, "applications")})
    assert sum(m["counts"].values()) == m["total"] and m["counts"]["crit"] and m["counts"]["ok"]
    words = {"crit": "At risk", "warn": "Partly protected", "ok": "Protected"}
    for t in tiles[:6]:
        assert words[t["tone"]] in client.get("/apps/" + t["host"]).text


def test_the_weakest_come_first(session):
    rank = {"crit": 0, "warn": 1, "ok": 2}
    m = report.protection_map(session)
    worst = [rank[g["tiles"][0]["tone"]] for g in m["gateways"]]
    assert worst == sorted(worst)
    for g in m["gateways"]:
        tones = [rank[t["tone"]] for t in g["tiles"]]
        assert tones == sorted(tones)


def test_overview_draws_the_map_without_a_script(client):
    html = client.get("/").text
    assert 'aria-label="Protection map"' in html and 'class="tile s-crit"' in html and "<script" not in html


def test_no_map_on_an_empty_console(console):
    assert "Protection map" not in console.get("/").text
