"""Change history between collections, and the score trend."""
import json

from conftest import EXAMPLES

from waf_inventory import findings, remedies, report
from waf_inventory.cli import collect_source
from waf_inventory.models import connect


def test_second_collection_records_what_changed(tmp_path):
    s = connect(str(tmp_path / "t.db"))
    bundle = json.loads((EXAMPLES / "baffinbay" / "bundle.json").read_text())
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    src = {"type": "baffinbay_bundle", "name": "bb", "path": str(path)}
    collect_source(s, {"_dir": tmp_path}, src)
    assert report.table(s, "changes") == []  # the first collection is not a change

    configs = bundle["traffic_configs"]["data"]
    portal = next(c for c in configs if c["attributes"]["name"] == "contoso-portal")
    portal["attributes"]["waf"]["enforcement"] = "LOG"
    portal["attributes"]["waf"]["paranoidLevel"] = 1
    bundle["traffic_configs"]["data"] = [c for c in configs if c["attributes"]["name"] != "contoso-careers"]
    path.write_text(json.dumps(bundle))
    collect_source(s, {"_dir": tmp_path}, src)

    got = {(r["change"], r["what"], r["subject"]): r for r in report.table(s, "changes")}
    pol = got[("changed", "policy", "baffinbay: contoso-portal")]
    assert pol["weakened"] == "yes" and "mode: block → detect" in pol["detail"] and "paranoia_level: 2 → 1" in pol["detail"]
    assert ("removed", "listener", "contoso-careers / frontend") in got and ("removed", "policy", "baffinbay: contoso-careers") in got
    assert got[("removed", "policy", "baffinbay: contoso-careers")]["weakened"] == "yes"  # it was blocking
    assert not any(k[0] == "added" for k in got) and len(got) == 4  # nothing else: unchanged routes are not reported
    assert report.table(s, "changes")[0]["weakened"] == "yes"  # weakened protection first


def test_score_history_keeps_one_point_per_run(tmp_path):
    s = connect(str(tmp_path / "t.db"))
    collect_source(s, {"_dir": EXAMPLES}, {"type": "baffinbay_bundle", "name": "bb", "path": "baffinbay/bundle.json"})
    findings.run(s)
    findings.run(s)  # within 10 minutes: replaces the point
    pts = remedies.score_history(s)
    assert len(pts) == 1 and pts[0]["score"] == remedies.plan(s)["score"]


def test_changes_page(client):
    page = client.get("/changes").text
    assert "Changes" in page and "Weakened protection (0)" in page and "No changes yet" in page
    assert client.get("/export/changes.csv").status_code == 200
