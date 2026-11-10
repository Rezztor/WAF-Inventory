"""Alerts: what a run gives to tell, delivery by webhook and email, and the Settings page."""
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from conftest import add, csrf, wait

from waf_inventory import alerts, findings, vault
from waf_inventory.cli import collect_source
from waf_inventory.models import AuditLog, Change, FindingState, Job, SourceConfig, connect, get_setting, put_setting, utcnow

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def hook():
    """A local webhook receiver: hook.url, hook.got (the JSON bodies), hook.status (what it answers)."""
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            server.got.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
            self.send_response(server.status)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.got, server.status, server.url = [], 200, f"http://127.0.0.1:{server.server_address[1]}/hook/s3cret-path"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def test_a_run_reports_weakened_protection_new_high_findings_and_failures(tmp_path):
    s = connect(str(tmp_path / "t.db"))
    start = utcnow() - timedelta(minutes=1)
    collect_source(s, {"_dir": EXAMPLES}, {"type": "baffinbay_bundle", "name": "bb", "path": "baffinbay/bundle.json"})
    findings.run(s)
    s.add(Change(time=utcnow(), source="bb", kind="changed", what="policy", subject="baffinbay: shop", detail="mode: block → detect", weakened=True))
    s.add(Change(time=utcnow(), source="bb", kind="added", what="route", subject="shop /new"))  # not weakened: no alert
    s.add(SourceConfig(name="bb", type="baffinbay_bundle", settings={}))
    s.commit()

    got = {e["event"]: e for e in alerts.gather(s, Job(source="bb", status="ok", started=start))}
    assert set(got) == {"weakened", "new_high"}
    assert got["weakened"]["items"] == ["policy baffinbay: shop: mode: block → detect"]
    high = s.query(FindingState).filter_by(severity="high").count()
    assert high and len(got["new_high"]["items"]) == min(high, alerts.MAX_ITEMS) + (high > alerts.MAX_ITEMS)
    assert alerts.gather(s, Job(source="bb", status="ok", started=utcnow() + timedelta(minutes=1))) == []  # nothing new since
    assert alerts.gather(s, Job(source="other", status="ok", started=start))[0]["event"] == "new_high"  # another source's changes

    failed = Job(source="bb", status="error", started=start, summary="Sign-in was refused")
    assert alerts.gather(s, failed) == [{"event": "run_failed", "title": "Collection of bb failed", "items": ["Sign-in was refused"]}]
    sc = s.query(SourceConfig).one()
    sc.settings = {"retry_at": utcnow().isoformat()}  # a retry is pending: not a failure yet
    s.commit()
    assert alerts.gather(s, failed) == []

    put_setting(s, "alerts", {"events": ["run_failed"]})
    assert alerts.gather(s, Job(source="bb", status="ok", started=start)) == []  # switched off

    subject, text = alerts.render(list(got.values()), "https://waf.example:8443/")
    assert subject == "WAF Inventory: Protection was weakened on bb (+1 more)"
    assert "  - policy baffinbay: shop: mode: block → detect" in text and text.endswith("Open the console: https://waf.example:8443/")


def test_expiry_warnings_are_repeated_only_weekly(tmp_path, monkeypatch):
    s = connect(str(tmp_path / "t.db"))
    monkeypatch.setattr(alerts.sources, "problems", lambda s, cert=None: [("x: the Azure client secret expires on 2030-01-01", "/sources/1"),
                                                                           ("x: last run failed. token expired", "/sources/1")])
    job = Job(source="x", status="ok", started=utcnow())
    events = alerts.gather(s, job)
    assert events == [{"event": "expiring", "title": "Expiring soon", "items": ["x: the Azure client secret expires on 2030-01-01"]}]
    assert alerts.gather(s, job) == events  # not delivered yet, so still due
    alerts.remember(s, events)
    assert alerts.gather(s, job) == []
    old = (alerts.date.today() - alerts.REMIND).isoformat()
    put_setting(s, "alerts_sent", {m: old for m in get_setting(s, "alerts_sent")})
    assert alerts.gather(s, job) == events  # a week later it is said again


def test_send_by_webhook_and_email(master_key, hook, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, **kw):
            sent.append(["connect", host, port])

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def starttls(self, context=None):
            sent.append(["starttls"])

        def login(self, user, password):
            sent.append(["login", user, password])

        def send_message(self, msg):
            sent.append(["message", msg["Subject"], msg["From"], msg["To"], msg.get_content()])

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    cfg = {**alerts.DEFAULT, "webhook": vault.seal(hook.url), "smtp_password": vault.seal("pw-123"), "base_url": "",
           "smtp": {"host": "smtp.example", "port": 587, "security": "starttls", "username": "waf", "sender": "waf@example.com",
                    "to": ["a@example.com", "b@example.com"]}}
    events = [{"event": "run_failed", "title": "Collection of bb failed", "items": ["Sign-in was refused"]}]
    assert alerts.send(cfg, events) == [("webhook", None), ("email", None)]
    assert hook.got[0]["title"] == "WAF Inventory: Collection of bb failed" and hook.got[0]["events"] == events
    assert hook.got[0]["text"].startswith("WAF Inventory: Collection of bb failed\n") and "Sign-in was refused" in hook.got[0]["text"]
    assert sent[:3] == [["connect", "smtp.example", 587], ["starttls"], ["login", "waf", "pw-123"]]
    assert sent[3][1:4] == ["WAF Inventory: Collection of bb failed", "waf@example.com", "a@example.com, b@example.com"]

    hook.status = 500  # one channel failing does not stop the other, and the error never shows the URL
    results = dict(alerts.send(cfg, events))
    assert results["email"] is None and results["webhook"] == "the webhook answered 500" and "s3cret" not in str(results)
    assert alerts.send({**alerts.DEFAULT}, events) == []  # nothing configured, nothing sent


def test_settings_page_saves_secrets_encrypted_and_sends_a_test(console, hook):
    c = console
    page = c.get("/settings/alerts").text
    assert "Alerts" in page and "Send an alert when" in page and page.count('" checked>') == len(alerts.EVENTS)
    bad = c.post("/settings/alerts", data={"csrf": csrf(c), "webhook": "ftp://x", "smtp_host": "smtp.example", "smtp_port": "99999"})
    assert bad.status_code == 422 and "must start with https://" in bad.text and "From address" in bad.text and "1 to 65535" in bad.text

    r = c.post("/settings/alerts", data={"csrf": csrf(c), "event_run_failed": "on", "event_weakened": "on", "webhook": hook.url,
                                         "base_url": "https://waf.example:8443", "action": "test"})
    assert r.status_code == 200 and "Webhook: sent" in r.text and "s3cret-path" not in r.text and "Saved. Leave blank to keep it" in r.text
    assert hook.got[-1]["events"][0]["event"] == "test" and "https://waf.example:8443/" in hook.got[-1]["text"]
    with connect(c.db) as s:
        cfg = alerts.config(s)
        assert cfg["events"] == ["weakened", "run_failed"] and "s3cret" not in json.dumps(cfg) and vault.unseal(cfg["webhook"]) == hook.url
        assert {a.action for a in s.query(AuditLog)} >= {"settings changed", "alert test sent"}
        assert "s3cret" not in json.dumps([a.detail for a in s.query(AuditLog)])

    # a failed collection is reported through the webhook and noted in the job log
    sid = add(c, "f5_offline", name="broken", path="nowhere")
    job = c.post(f"/sources/{sid}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"]
    assert "Alert sent by webhook: Collection of broken failed" in wait(c, job)
    assert hook.got[-1]["events"][0]["event"] == "run_failed" and "Not found on the server" in hook.got[-1]["text"]

    # a blank URL keeps the saved one; the tick box removes it
    c.post("/settings/alerts", data={"csrf": csrf(c), "event_run_failed": "on"})
    with connect(c.db) as s:
        assert vault.unseal(alerts.config(s)["webhook"]) == hook.url
    c.post("/settings/alerts", data={"csrf": csrf(c), "webhook_remove": "on"})
    with connect(c.db) as s:
        assert alerts.config(s)["webhook"] is None and alerts.config(s)["events"] == []
    assert "set a webhook or an email server first" in c.post("/settings/alerts", data={"csrf": csrf(c), "action": "test"}).text
