import shutil
from pathlib import Path

import pytest

from waf_inventory.cli import main
from waf_inventory.models import connect

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
