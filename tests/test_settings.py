"""Settings › Data collection, time zones, retries, Azure clouds, F5 port / token / partitions, SSH and file uploads."""
import io
import socket
import tarfile
import threading
import time
from datetime import datetime, timedelta

import paramiko
import pytest
from conftest import EXAMPLES, add, csrf, wait
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from waf_inventory import azure, f5, jobs, sources, vault
from waf_inventory.models import Job, SourceConfig, connect, get_setting

D = datetime(2026, 10, 21, 10, 30)  # a Wednesday, UTC
WHEN = {"schedule_every": "weekly", "schedule_day": "6", "schedule_at": "02:00", "schedule_tz": "Asia/Dubai"}
VERSION = "Sys::Version\nMain Package\n  Product     BIG-IP\n  Version     17.1.2\n  Build       0.0.8\n"


def test_next_run_in_a_time_zone():
    dubai = {"every": "daily", "at": "02:00", "tz": "Asia/Dubai"}  # UTC+4, no daylight saving
    assert sources.next_run(dubai, D) == datetime(2026, 10, 21, 22, 0)
    assert sources.next_run({**dubai, "every": "weekly", "day": 6}, D) == datetime(2026, 10, 24, 22, 0)  # Sunday 02:00 Dubai
    london = {"every": "daily", "at": "02:00", "tz": "Europe/London"}
    assert sources.next_run(london, datetime(2026, 10, 24, 12, 0)) == datetime(2026, 10, 25, 2, 0)  # clocks went back that night
    assert sources.next_run({"every": "default"}, D) is None
    assert sources.describe({"every": "default"}, {**sources.COLLECTION, **dubai}) == "Daily at 02:00 (Asia/Dubai)"


def test_default_schedule_drives_connections_that_use_it(console):
    c = console
    sid = add(c, "logs", name="logs", path="logs/*.jsonl", schedule_mode="default")
    own = add(c, "logs", name="own", path="logs/*.jsonl", schedule_mode="own", schedule_every="daily", schedule_at="05:00",
              schedule_day="0", schedule_tz="UTC")
    assert "Daily at 02:00 (UTC)" in c.get("/sources").text
    r = c.post("/settings", data={"csrf": csrf(c, "/settings"), "collapse_threshold": "10", "min_hits": "5", "job_retention_days": "90",
                                  **WHEN, "retry": "on"}, follow_redirects=False)
    assert r.status_code == 303
    with connect(c.db) as s:
        assert sources.collection(s) == {"every": "weekly", "at": "02:00", "day": 6, "tz": "Asia/Dubai", "catch_up": False, "retry": True}
        nxt = datetime.fromisoformat(s.get(SourceConfig, sid).settings["next_run"])
        assert nxt.weekday() == 5 and nxt.hour == 22  # Saturday 22:00 UTC is Sunday 02:00 in Dubai
        assert s.get(SourceConfig, own).settings["next_run"].endswith("05:00:00")
    page = c.get("/settings").text
    assert "Weekly, Sunday at 02:00 (Asia/Dubai)" in page and page.count("UTC ·") == 2  # three next runs listed
    bad = c.post("/settings", data={"csrf": csrf(c, "/settings"), "collapse_threshold": "10", "min_hits": "5", "job_retention_days": "90",
                                    **WHEN, "schedule_tz": "Mars/Olympus"})
    assert bad.status_code == 422 and "time zone" in bad.text


def test_missed_runs_and_retries(console):
    c = console
    sid = add(c, "f5_offline", name="broken", path="nowhere", schedule_mode="own", schedule_every="daily", schedule_at="02:00",
              schedule_day="0", schedule_tz="UTC")
    with connect(c.db) as s:
        real = jobs.Runner(s.get_bind(), {"_dir": c.dir})

        class runner:  # queue only; the test runs the job itself
            @staticmethod
            def submit(s, sc, trigger):
                s.add(Job(source=sc.name, trigger=trigger, created=datetime.now()))
                s.commit()
        sc = s.get(SourceConfig, sid)
        nxt = datetime.fromisoformat(sc.settings["next_run"])
        sc.settings = {**sc.settings, "next_run": (nxt - timedelta(days=2)).isoformat()}  # the server was off two days ago
        s.commit()
        assert jobs.tick(s, runner, nxt) == ["broken"]  # catch-up is on by default
        job = s.query(Job).one()
        real.run(job.id)
        s.expire_all()
        retry = datetime.fromisoformat(s.get(SourceConfig, sid).settings["retry_at"])
        assert "Will try again" in s.get(Job, job.id).log
        assert jobs.tick(s, runner, retry - timedelta(minutes=1)) == [] and jobs.tick(s, runner, retry) == ["broken"]
        assert s.query(Job).order_by(Job.id.desc()).first().trigger == "retry"
        assert "retry_at" not in s.get(SourceConfig, sid).settings

        from waf_inventory.models import put_setting
        put_setting(s, "collection", {**sources.COLLECTION, "catch_up": False})
        sc = s.get(SourceConfig, sid)
        sc.settings = {**sc.settings, "next_run": (nxt - timedelta(hours=3)).isoformat()}
        s.commit()
        assert jobs.tick(s, runner, nxt) == []  # missed while off: skipped, and the next one is booked
        assert datetime.fromisoformat(s.get(SourceConfig, sid).settings["next_run"]) > nxt


def test_azure_cloud_and_managed_identity(console):
    c = console
    gov = azure.Arm(object(), cloud="usgov")
    assert (gov.arm, gov.logs) == ("https://management.usgovcloudapi.net", "https://api.loganalytics.us")
    r = c.post("/sources/new/azure", data={"csrf": csrf(c), "name": "az", "cloud": "usgov", "auth": "secret", "log_days": "30"})
    assert r.status_code == 422 and "Tenant ID is required" in r.text
    sid = add(c, "azure", name="mi", cloud="usgov", auth="managed_identity", mi_client_id="33333333-3333-3333-3333-333333333333",
              log_days="30")
    with connect(c.db) as s:
        sc = s.get(SourceConfig, sid)
        assert type(sources.azure_credential(sc)).__name__ == "ManagedIdentityCredential" and not sources.secret_state(sc)
        sc.settings = {**sc.settings, "auth": "secret", "tenant_id": "t", "client_id": "c"}
        vault.put(sc, "client_secret", "x" * 20)
        assert type(sources.azure_credential(sc)).__name__ == "ClientSecretCredential"
    assert "Managed identity" in c.get("/sources").text


def test_f5_port_token_and_partitions():
    assert f5.address("10.0.0.5", 443) == "10.0.0.5" and f5.address("10.0.0.5", 8443) == "10.0.0.5:8443"
    assert f5.address("10.0.0.5:9443", 8443) == "10.0.0.5:9443"
    client = f5.F5Client("10.0.0.5", "u", "p", token=False)
    client.login()
    assert client.http.auth is not None and client.token is None
    cfg = f5.load_offline(EXAMPLES / "f5")
    only = f5.only_partitions(cfg, ["Partner"])
    assert only["asm"] and all(n.startswith("/Partner/") for n in only["asm"])
    assert all(v["name"].startswith("/Partner/") for v in only["virtuals"])
    assert f5.only_partitions(cfg, []) is cfg


def fake_tmsh(conf: str, bash: bool = True):
    """A BIG-IP account's answers: `tmsh -q -c "..."` from bash, or bare commands when tmsh is the login shell."""
    seen = []

    def run(cmd: str):
        seen.append(cmd)
        if cmd.startswith("tmsh") != bash:
            return 1, "Syntax Error: unexpected argument"
        body = cmd.removeprefix('tmsh -q -c "').rstrip('"')
        if body == "show sys version":
            return 0, VERSION
        if body == "cd /; list asm policy recursive":
            return 1, "01020036:3: The requested module (asm) is not provisioned"
        return (0, conf) if body == "cd /; list ltm virtual recursive" else (0, "")
    return run, seen


@pytest.mark.parametrize("bash", [True, False])
def test_ssh_reads_tmsh_like_bigip_conf(bash):
    run, seen = fake_tmsh((EXAMPLES / "f5" / "bigip.conf").read_text(), bash)
    cfg, warnings = f5.fetch_ssh(run)
    assert cfg["device"]["version"] == "17.1.2 0.0.8" and cfg["virtuals"] and cfg["asm"]
    assert warnings == ["tmsh list asm policy: 01020036:3: The requested module (asm) is not provisioned"]
    assert all(x.startswith("tmsh -q -c") == bash for x in seen[-8:])
    gateways, policies = f5.build(cfg)
    assert gateways[0].name == "dc1-bigip01.corp.contoso.com" and policies


class _Bigip(paramiko.ServerInterface):
    """Just enough of an SSH server: one user, one key or password, exec answered by fake_tmsh."""

    def __init__(self, pub, run):
        self.pub, self.run = pub, run

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL if username == "auditor" and key.asbytes() == self.pub.asbytes() else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("auditor", "Ssh-Pass-123") else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        status, out = self.run(command.decode())

        def answer():
            time.sleep(0.1)  # after the server has acknowledged the exec request
            channel.sendall(out.encode())
            channel.send_exit_status(status)
            channel.close()
        threading.Thread(target=answer, daemon=True).start()
        return True


def test_ssh_connection_pins_the_host_key_end_to_end(console):
    c = console
    host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(_openssh_key()))
    client_pem = _openssh_key()
    client_pub = paramiko.Ed25519Key.from_private_key(io.StringIO(client_pem))
    run, _ = fake_tmsh((EXAMPLES / "f5" / "bigip.conf").read_text())
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def session(conn):
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        try:
            t.start_server(server=_Bigip(client_pub, run))
        except (paramiko.SSHException, EOFError):
            pass  # Fetch host key hangs up straight after the key exchange

    def serve():
        while True:
            threading.Thread(target=session, args=(sock.accept()[0],), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    port = sock.getsockname()[1]

    assert "Private key is required" in c.post("/sources/new/f5_ssh", data={
        "csrf": csrf(c), "name": "dmz", "host": "127.0.0.1", "port": str(port), "username": "auditor", "ssh_auth": "key"}).text
    assert "cannot be read" in c.post("/sources/new/f5_ssh", data={
        "csrf": csrf(c), "name": "dmz", "host": "127.0.0.1", "port": str(port), "username": "auditor", "ssh_auth": "key",
        "ssh_key": "not a key"}).text
    sid = add(c, "f5_ssh", name="dmz", host="127.0.0.1", port=str(port), username="auditor", ssh_auth="key", ssh_key=client_pem)
    assert "host key is not trusted yet" in c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)}).text
    page = c.post(f"/sources/{sid}/ssh/fetch-key", data={"csrf": csrf(c)}).text
    fp = sources.ssh_fingerprint(host_key.asbytes())
    assert fp in page and "trust this host key" in page
    assert c.post(f"/sources/{sid}/ssh/trust-key", data={"csrf": csrf(c), "key_type": "ssh-ed25519", "key": host_key.get_base64(),
                                                          "fingerprint": "SHA256:wrong"}).status_code == 400
    c.post(f"/sources/{sid}/ssh/trust-key", data={"csrf": csrf(c), "key_type": "ssh-ed25519", "key": host_key.get_base64(),
                                                   "fingerprint": fp})
    t = c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)}).text
    assert "the host key matches. BIG-IP 17.1.2" in t
    job = c.post(f"/sources/{sid}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"]
    assert "Findings recomputed" in wait(c, job) and "asm) is not provisioned" in c.get(job).text
    with connect(c.db) as s:
        assert vault.get(s.get(SourceConfig, sid), "ssh_key") == client_pem.strip()
        sc = s.get(SourceConfig, sid)
        sc.settings = {**sc.settings, "host_key": "ssh-ed25519 " + paramiko.Ed25519Key.from_private_key(
            io.StringIO(_openssh_key())).get_base64()}  # the device now presents a different key
        s.commit()
    assert "host key has changed" in c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)}).text
    assert b"OPENSSH PRIVATE KEY" not in open(c.db, "rb").read()


def _openssh_key() -> str:
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()


def test_offline_files_uploaded_from_the_browser(console):
    c = console
    conf = (EXAMPLES / "f5" / "bigip.conf").read_bytes()
    ucs = io.BytesIO()
    with tarfile.open(fileobj=ucs, mode="w:gz") as tar:
        for name, data in (("config/bigip.conf", conf), ("../../evil.conf", b"x"), ("var/secret.txt", b"x")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    t = c.post("/sources/new/f5_offline", data={"csrf": csrf(c), "name": "dc2"}).text
    assert "Upload the device" in t
    bad = c.post("/sources/new/f5_offline", data={"csrf": csrf(c), "name": "dc2"}, files=[("files", ("run.sh", b"x"))])
    assert bad.status_code == 422 and "not a .conf" in bad.text
    r = c.post("/sources/new/f5_offline", data={"csrf": csrf(c), "name": "dc2", "path": ""}, follow_redirects=False,
               files=[("files", ("dc2.ucs", ucs.getvalue())),
                      *[("files", (p.name, p.read_bytes())) for p in sorted((EXAMPLES / "f5" / "asm").glob("*.json"))]])
    assert r.status_code == 303, r.text
    sid = int(r.headers["location"].split("/")[2].split("?")[0])
    folder = c.dir / "uploads" / str(sid)
    assert sorted(p.name for p in folder.iterdir()) == ["app1_api_waf.json", "app1_waf.json", "bigip.conf", "hr_waf.json",
                                                         "intranet_waf.json"]
    assert not (c.dir / "evil.conf").exists()
    assert "Connection works." in c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)}).text
    r = c.post(f"/sources/{sid}", data={"csrf": csrf(c), "path": str(folder), "schedule_mode": "off"},
               files=[("files", ("extra.txt", b"# tmsh output\n"))], follow_redirects=False)
    assert r.headers["location"].endswith("msg=uploaded") and (folder / "extra.txt").exists()
    with connect(c.db) as s:
        assert s.query(Job).filter_by(trigger="upload").count() == 1


def test_fonts_are_public_and_run_all(console):
    c = console
    assert c.get("/fonts/plus-jakarta-sans-latin.woff2").status_code == 200
    assert c.get("/fonts/..%2F..%2Fweb.py").status_code == 404 and c.get("/fonts/OFL.txt").status_code == 200
    add(c, "logs", name="a", path="logs/*.jsonl")
    add(c, "logs", name="b", path="logs/*.jsonl")
    assert c.post("/jobs/run-all", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"] == "/jobs"
    with connect(c.db) as s:
        assert sorted(j.source for j in s.query(Job)) == ["a", "b"] and get_setting(s, "collection") == {}
