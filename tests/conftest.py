from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import create_app

@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(str(tmp_path / "test.sqlite"), demo_mode=True)
    with TestClient(app) as instance:
        yield instance

@pytest.fixture()
def acme_operator():
    return {"Authorization": "Bearer local-acme-operator"}

@pytest.fixture()
def acme_admin():
    return {"Authorization": "Bearer local-acme-admin"}

@pytest.fixture()
def nova_operator():
    return {"Authorization": "Bearer local-nova-operator"}

@pytest.fixture()
def nova_admin():
    return {"Authorization": "Bearer local-nova-admin"}

@pytest.fixture()
def acme_viewer():
    return {"Authorization": "Bearer local-acme-viewer"}