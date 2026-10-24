import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from waf_inventory import auth
from waf_inventory.cli import main
from waf_inventory.models import connect
from waf_inventory.web import create_app

PASSWORD = "correct horse battery"

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(scope="session")
def demo_db(tmp_path_factory) -> str:
    """The full demo collected once: Azure bundle + F5 offline + sample logs."""
    d = tmp_path_factory.mktemp("demo")
    shutil.copytree(EXAMPLES, d, dirs_exist_ok=True)
    cfg = d / "demo.toml"
    cfg.write_text(cfg.read_text().replace('database = "demo.db"', f'database = "{d / "t.db"}"'))
    assert main(["-c", str(cfg), "collect"]) == 0
    return str(d / "t.db")


@pytest.fixture
def session(demo_db):
    s = connect(demo_db)
    yield s
    s.close()


@pytest.fixture
def client(demo_db) -> TestClient:
    """Dashboard client signed in as admin."""
    with connect(demo_db) as s:
        auth.set_password(s, "admin", PASSWORD)
    c = TestClient(create_app(demo_db))
    assert c.post("/login", data={"username": "admin", "password": PASSWORD}).status_code == 200
    return c
