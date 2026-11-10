import io
import tarfile
import zipfile

import pytest

from vulnscope.adapters.inbound.http.app import create_app
from vulnscope.bootstrap import build_container
from vulnscope.config import Settings
from vulnscope.domain.errors import AIUnavailableError


class FakeAI:
    name = "fake-ai"

    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def complete(self, system, user):
        self.calls.append((system, user))
        if self.fail:
            raise AIUnavailableError("down")
        return "FAKE AI ANSWER"


@pytest.fixture
def ai():
    return FakeAI()


@pytest.fixture
def client(tmp_path, ai):
    s = Settings(env="development", db_path=str(tmp_path / "t.db"), secret_key="k" * 40)
    s.finalize()
    app = create_app(s, build_container(s, ai_client=ai))
    app.testing = False  # exercise real error handlers
    return app.test_client()


@pytest.fixture
def auth(client):
    t = client.post("/login", json={"username": "admin", "clave": "demo123"}).get_json()["token"]
    return {"Authorization": f"Bearer {t}"}


def vuln(**kw):
    d = {"titulo": "SQL Injection en login", "cve_codigo": "CVE-2024-12345", "severidad": "alta",
         "estado": "abierta", "puntaje_cvss": 8.1}
    d.update(kw)
    return d


VULN_CODE = ("import pickle\napp.config['SECRET_KEY'] = 'SuperSecretValue123'\n"
             "cur.execute(\"SELECT * FROM t WHERE id=\" + uid)\napp.run(debug=True)\nd = pickle.loads(blob)\n")


def make_zip(files: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in files.items():
            z.writestr(n, c)
    return b.getvalue()


def make_tgz(files: dict) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n, c in files.items():
            i = tarfile.TarInfo(n)
            i.size = len(c)
            t.addfile(i, io.BytesIO(c.encode()))
    return b.getvalue()
