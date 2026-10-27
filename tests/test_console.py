"""Schedules, warnings, certificate rotation, pickers, audit log, settings, import/export, HTTPS certificate."""
import time
from datetime import date, datetime, timedelta, timezone

import pytest
from conftest import PASSWORD, add, csrf, wait
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from waf_inventory import auth, jobs, report, sources, tls, vault
from waf_inventory.models import AuditLog, Job, SourceConfig, connect, get_setting
from waf_inventory.web import create_app

D = datetime(2026, 10, 21, 10, 30)  # a Wednesday


def test_next_run():
    assert sources.next_run({"every": "off"}, D) is None
    assert sources.next_run({"every": "hourly"}, D) == datetime(2026, 10, 21, 11, 0)
    assert sources.next_run({"every": "daily", "at": "02:00"}, D) == datetime(2026, 10, 22, 2, 0)
    assert sources.next_run({"every": "daily", "at": "23:15"}, D) == datetime(2026, 10, 21, 23, 15)
    assert sources.next_run({"every": "weekly", "at": "02:00", "day": 0}, D) == datetime(2026, 10, 26, 2, 0)  # next Monday
    assert sources.next_run({"every": "weekly", "at": "11:00", "day": 2}, D) == datetime(2026, 10, 21, 11, 0)  # later today


def test_schedule_queues_due_sources_and_prunes_history(console):
    c = console
    sid = add(c, "f5_offline", name="bigip", path="f5", schedule_every="daily", schedule_at="02:00", schedule_day="0")
    add(c, "logs", name="manual", path="logs/*.jsonl")
    assert "Next run" in c.get(f"/sources/{sid}").text
    with connect(c.db) as s:
        engine = s.get_bind()
        runner = jobs.Runner(engine, {"_dir": c.dir})
        sc = s.get(SourceConfig, sid)
        nxt = datetime.fromisoformat(sc.settings["next_run"])
        assert jobs.tick(s, runner, nxt - timedelta(minutes=1)) == []
        s.add(Job(source="old", created=nxt - timedelta(days=400), finished=nxt - timedelta(days=400), status="ok"))
        s.commit()
        assert jobs.tick(s, runner, nxt) == ["bigip"]
        assert datetime.fromisoformat(s.get(SourceConfig, sid).settings["next_run"]) == nxt + timedelta(days=1)
        assert {j.trigger for j in s.query(Job)} == {"schedule"}  # the 400-day-old job is gone; "manual" never queued


def test_problems_list_failures_and_expiring_credentials(console):
    c = console
    soon = (date.today() + timedelta(days=10)).isoformat()
    sid = add(c, "azure", name="az", tenant_id="t", client_id="c", auth="secret", client_secret="x" * 20, client_secret_expires=soon,
              log_days="30")
    bad = add(c, "f5_offline", name="broken", path="nowhere")
    wait(c, c.post(f"/sources/{bad}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"])
    for url in ("/", "/sources"):
        page = c.get(url).text
        assert "2 things need attention" in page and f"Azure client secret expires on {soon}" in page and "broken: last run failed" in page
        assert f'href="/sources/{sid}"' in page


def test_azure_certificate_rotation_waits_for_a_passing_test(console, monkeypatch):
    c = console
    sid = add(c, "azure", name="az", tenant_id="t", client_id="c", auth="certificate", log_days="30")
    with connect(c.db) as s:
        old = sources.secret_state(s.get(SourceConfig, sid))["certificate"]["meta"]["thumbprint"]
    c.post(f"/sources/{sid}/azure/certificate", data={"csrf": csrf(c)})
    with connect(c.db) as s:
        st = sources.secret_state(s.get(SourceConfig, sid))
        assert st["certificate"]["meta"]["thumbprint"] == old and "certificate_next" in st
        new = st["certificate_next"]["meta"]["thumbprint"]
    assert "Test the new certificate" in c.get(f"/sources/{sid}").text
    assert x509.load_der_x509_certificate(c.get(f"/sources/{sid}/azure/certificate.cer?next=1").content).fingerprint(
        hashes.SHA1()).hex().upper() == new
    seen = []
    monkeypatch.setattr(sources, "test", lambda cfg, sc, certificate: (seen.append(certificate), (["fine"], None))[1])
    r = c.post(f"/sources/{sid}/test", data={"csrf": csrf(c), "certificate": "certificate_next"})
    assert seen == ["certificate_next"] and "now in use" in r.text
    with connect(c.db) as s:
        st = sources.secret_state(s.get(SourceConfig, sid))
        assert st["certificate"]["meta"]["thumbprint"] == new and "certificate_next" not in st


def test_subscription_and_workspace_pickers(console, monkeypatch):
    c = console
    sid = add(c, "azure", name="az", tenant_id="t", client_id="c", auth="certificate", log_days="30")
    found = {"subscriptions": [("sub-1", "Prod"), ("sub-2", "Dev")],
             "workspaces": [{"id": "ws-guid-1", "name": "law-prod", "subscription": "Prod"}]}
    monkeypatch.setattr(sources, "test", lambda cfg, sc, certificate: (["Signed in."], found))
    page = c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)}).text
    assert "Choose what to collect" in page and 'value="sub-2"' in page and "law-prod" in page
    c.post(f"/sources/{sid}/scope", data={"csrf": csrf(c), "subscriptions": ["sub-1", "sub-2"], "log_workspaces": "ws-guid-1"})
    with connect(c.db) as s:
        st = s.get(SourceConfig, sid).settings
        assert st["subscriptions"] == ["sub-1", "sub-2"] and st["log_workspaces"] == ["ws-guid-1"]


def test_audit_log_records_actions_without_secrets(console):
    c = console
    sid = add(c, "f5_rest", name="bigip", host="192.0.2.1", username="auditor", password="Audit-Secret-99")
    c.post(f"/sources/{sid}", data={"csrf": csrf(c), "host": "192.0.2.2", "username": "auditor", "password": "Audit-Secret-100"})
    with connect(c.db) as s:
        rows = {(a.action, a.target): a.detail for a in s.query(AuditLog)}
        assert ("signed in", "") in rows and ("source added", "bigip") in rows
        assert rows[("source changed", "bigip")] == {"settings": ["host"], "secrets": ["password"]}
    assert b"Audit-Secret" not in open(c.db, "rb").read()
    page = c.get("/audit?action=source+changed").text
    assert "source changed" in page and "source added</td>" not in page
    assert c.get("/audit?format=csv").text.startswith("time,user,ip,action,target,detail")


def test_general_settings_feed_the_next_run(console):
    c = console
    when = {"schedule_every": "weekly", "schedule_day": "6", "schedule_at": "02:00", "schedule_tz": "UTC", "retry": "on"}
    assert c.post("/settings", data={"csrf": csrf(c, "/settings"), "collapse_threshold": "x", "min_hits": "5",
                                     "job_retention_days": "90", **when}).status_code == 422
    c.post("/settings", data={"csrf": csrf(c, "/settings"), "collapse_threshold": "4", "min_hits": "2", "job_retention_days": "30", **when})
    with connect(c.db) as s:
        assert get_setting(s, "general") == {"collapse_threshold": 4, "min_hits": 2, "job_retention_days": 30}
        assert jobs.effective_cfg(s, {"_dir": c.dir, "discovery": {"min_hits": 9, "overrides": {"a": []}}})["discovery"] == \
            {"min_hits": 2, "collapse_threshold": 4, "overrides": {"a": []}}


def test_password_change_signs_out_everywhere(console):
    c = console
    token = csrf(c, "/settings/account")
    assert "current password is wrong" in c.post("/settings/account", data={"csrf": token, "current": "nope", "new": "x" * 12,
                                                                                "again": "x" * 12}).text
    r = c.post("/settings/account", data={"csrf": token, "current": PASSWORD, "new": "a brand new passphrase",
                                          "again": "a brand new passphrase"}, follow_redirects=False)
    assert r.headers["location"] == "/login?changed=1"
    assert c.get("/", follow_redirects=False).status_code == 303
    assert "Password changed" in c.get("/login?changed=1").text
    assert c.post("/login", data={"username": "admin", "password": "a brand new passphrase"}, follow_redirects=False).status_code == 303


def test_toml_export_and_import(console, tmp_path, monkeypatch):
    c = console
    add(c, "f5_rest", name="bigip", host="192.0.2.1", username="auditor", password="Export-Secret-1",
        schedule_every="weekly", schedule_at="03:30", schedule_day="6")
    add(c, "azure", name="az", tenant_id="t", client_id="c", auth="certificate", subscriptions="s1\ns2", log_days="14")
    exported = c.get("/settings/export.toml").text
    assert "Export-Secret" not in exported and "PRIVATE KEY" not in exported and "# password: not exported" in exported
    import tomllib
    assert [x["name"] for x in tomllib.loads(exported)["sources"]] == ["az", "bigip"]

    db = str(tmp_path / "other.db")
    with connect(db) as s:
        auth.set_password(s, "admin", PASSWORD)
    other = TestClient(create_app(db, {"_dir": tmp_path}))
    other.post("/login", data={"username": "admin", "password": PASSWORD})
    page = other.post("/settings/import", data={"csrf": csrf(other, "/settings/transfer"), "toml": exported}).text
    assert "Added: az, bigip" in page
    assert "Skipped" in other.post("/settings/import", data={"csrf": csrf(other, "/settings/transfer"), "toml": exported}).text
    assert "Not imported" in other.post("/settings/import", data={"csrf": csrf(other, "/settings/transfer"), "toml": "[[x"}).text
    with connect(db) as s:
        bigip = s.query(SourceConfig).filter_by(name="bigip").one()
        assert bigip.settings["schedule"] == {"every": "weekly", "at": "03:30", "day": 6, "tz": "UTC"} and bigip.settings["next_run"]
        assert s.query(SourceConfig).filter_by(name="az").one().settings["subscriptions"] == ["s1", "s2"]



def test_imported_secrets_go_to_the_vault_and_never_back_out(console):
    c = console
    toml = ('[[sources]]\nname = "bigip"\ntype = "f5_rest"\nhost = "192.0.2.1"\nusername = "auditor"\npassword = "Inline-Secret-1"\n'
            '[[sources]]\nname = "az"\ntype = "azure"\ntenant_id = "t"\nclient_id = "c"\nauth = "secret"\n'
            'client_secret = "Inline-Secret-2"\nclient_secret_expires = 2030-01-31\n')
    assert "Added: bigip, az" in c.post("/settings/import", data={"csrf": csrf(c, "/settings/transfer"), "toml": toml}).text
    exported = c.get("/settings/export.toml").text
    assert "Inline-Secret" not in exported and "# client_secret: not exported" in exported
    with connect(c.db) as s:
        bigip, az = (s.query(SourceConfig).filter_by(name=n).one() for n in ("bigip", "az"))
        assert "password" not in bigip.settings and vault.get(bigip, "password") == "Inline-Secret-1"
        assert "client_secret" not in az.settings and vault.get(az, "client_secret") == "Inline-Secret-2"
        assert az.settings["client_secret_expires"] == "2030-01-31"
    assert all(b"Inline-Secret" not in f.read_bytes() for f in c.dir.glob("console.db*"))


@pytest.mark.parametrize("entry, why", [
    ('type = "logs"\npath = 5', "path is not a valid text"),
    ('type = "logs"\npath = "x"\nschedule = "daily"', "schedule needs"),
    ('type = "logs"\npath = "x"\nschedule = { every = "daily", at = 2 }', "schedule needs"),
    ('type = "azure"\nclient_secret_expires = "2026-13-45"', "client_secret_expires is not a valid date"),
    ('type = "azure"\nlog_days = "30"', "log_days is not a valid int"),
    ('type = "azure"\nsubscriptions = [1]', "subscriptions is not a valid list"),
    ('type = "f5_rest"\nca_cert = 1', "ca_cert is not text"),
])
def test_import_refuses_wrong_values_in_plain_words(console, entry, why):
    c = console
    r = c.post("/settings/import", data={"csrf": csrf(c, "/settings/transfer"), "toml": f'[[sources]]\nname = "x"\n{entry}\n'})
    assert r.status_code == 422 and f"Not imported: x: {why}" in r.text
    with connect(c.db) as s:
        assert not s.query(SourceConfig).count()


def test_a_bad_date_is_refused_and_never_breaks_the_pages(console):
    c = console
    r = c.post("/sources/new/azure", data={"csrf": csrf(c), "name": "az", "tenant_id": "t", "client_id": "c", "auth": "secret",
                                          "client_secret": "x" * 20, "client_secret_expires": "2026-13-45", "log_days": "30"})
    assert r.status_code == 422 and "Client secret expires on must be a date" in r.text
    sid = add(c, "azure", name="az", tenant_id="t", client_id="c", auth="secret", client_secret="x" * 20, log_days="30")
    with connect(c.db) as s:  # a value stored before dates were checked
        sc = s.get(SourceConfig, sid)
        sc.settings = {**sc.settings, "client_secret_expires": "2026-13-45"}
        s.commit()
    assert c.get("/").status_code == 200 and c.get("/sources").status_code == 200


def test_a_source_is_not_deleted_under_a_running_job(console, monkeypatch):
    c = console
    sid = add(c, "logs", name="logs", path="logs/*.jsonl")
    with connect(c.db) as s:
        s.add(Job(source="logs", created=datetime.now(), status="running"))
        s.commit()
    r = c.post(f"/sources/{sid}/delete", data={"csrf": csrf(c), "password": PASSWORD})
    assert r.status_code == 409 and "queued or running" in r.text
    with connect(c.db) as s:
        s.query(Job).update({"status": "ok"})
        s.commit()
        assert c.post(f"/sources/{sid}/delete", data={"csrf": csrf(c), "password": PASSWORD}).status_code == 200

    # deleted anyway while collecting (a race): the job fails cleanly, nothing comes back and the worker keeps going
    sid = add(c, "logs", name="logs", path="logs/*.jsonl")

    def vanish(s, cfg, sc, log):
        with connect(c.db) as other:
            other.delete(other.get(SourceConfig, sc.id))
            other.commit()
        raise RuntimeError("connection lost")
    monkeypatch.setattr(sources, "collect", vanish)
    with connect(c.db) as s:
        runner = jobs.Runner(s.get_bind(), {"_dir": c.dir})
        job = runner.submit(s, s.get(SourceConfig, sid))
        for _ in range(200):
            if s.get(Job, job.id, populate_existing=True).status not in jobs.ACTIVE:
                break
            time.sleep(0.05)
        assert s.get(Job, job.id).summary == "RuntimeError: connection lost"
        assert report.table(s, "sources") == [] and runner.thread.is_alive()
    monkeypatch.setattr(jobs.Runner, "run", lambda self, job_id: 1 / 0)
    runner.q.put(0)
    time.sleep(0.2)
    assert runner.thread.is_alive()

def test_https_certificate_from_internal_ca_in_the_browser(console, tmp_path):
    c = console
    assert "plain HTTP" in c.get("/settings/security").text
    tls_dir = tmp_path / "tls"
    first, _ = tls.ensure_cert(tls_dir)
    app = create_app(c.db, {"_dir": c.dir}, tls_dir=str(tls_dir))
    reloaded = []
    app.state.reload_tls = lambda: reloaded.append(True)
    b = TestClient(app)
    b.post("/login", data={"username": "admin", "password": PASSWORD})
    page = b.get("/settings/security").text
    assert tls.fingerprint(first) in page and "Self-signed" in page
    page = b.post("/settings/security/csr", data={"csrf": csrf(b, "/settings/security"), "names": "waf.corp.example, 10.0.0.5"}).text
    csr = x509.load_pem_x509_csr(page.split("<textarea rows=\"10\" readonly>")[1].split("</textarea>")[0].encode())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["waf.corp.example"] and [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5"]
    assert "does not match" in b.post("/settings/security/install", data={"csrf": csrf(b, "/settings/security"),
                                                                          "chain": first.read_text()}).text
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Corp CA")])
    t = datetime.now(timezone.utc)
    leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca).public_key(csr.public_key()).serial_number(7)
            .not_valid_before(t).not_valid_after(t + timedelta(days=20)).add_extension(san, critical=False).sign(ca_key, hashes.SHA256()))
    r = b.post("/settings/security/install", data={"csrf": csrf(b, "/settings/security"),
                                                   "chain": leaf.public_bytes(serialization.Encoding.PEM).decode()}, follow_redirects=False)
    assert r.status_code == 303 and reloaded == [True]
    page = b.get("/settings/security").text
    assert "Corp CA" in page and "waf.corp.example" in page
    assert "HTTPS certificate expires" in b.get("/").text  # 20 days left: warned on the overview


@pytest.mark.parametrize("url", ["/settings", "/settings/security", "/settings/account", "/settings/transfer", "/audit"])
def test_settings_pages_need_sign_in(console, url):
    anon = TestClient(console.app)
    assert anon.get(url, follow_redirects=False).status_code == 303
    assert console.get(url).status_code == 200
