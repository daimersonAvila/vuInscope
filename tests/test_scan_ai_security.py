import io
import zipfile

from conftest import VULN_CODE, make_tgz, make_zip, vuln


def post_archive(client, data, name="p.zip"):
    return client.post("/api/scan", data={"archive": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_scan_zip_finds_and_redacts(client):
    r = post_archive(client, make_zip({"proj/app.py": VULN_CODE, "proj/.env": "X=1", "proj/.venv/lib/a.py": "eval(x)"}))
    d = r.get_json()
    assert r.status_code == 200
    ids = {f["rule_id"] for f in d["findings"]}
    assert {"SEC003", "INJ001", "CFG001", "EXE002", "FIL001"} <= ids
    assert ".venv" in d["stats"]["ignored_dirs"] and "FIL004" in ids
    assert "SuperSecretValue123" not in r.get_data(as_text=True)
    assert 0 < d["risk"]["score"] <= 100 and d["risk"]["most_likely_path"][-1] == "compromised"


def test_scan_targz(client):
    d = post_archive(client, make_tgz({"a/app.py": VULN_CODE}), "p.tar.gz").get_json()
    assert d["stats"]["total"] >= 3


def test_zip_slip_entries_skipped(client):
    d = post_archive(client, make_zip({"../../etc/evil.py": "eval(x)", "ok.py": "print(1)"})).get_json()
    assert d["stats"]["skipped_unsafe"] == 1 and d["stats"]["total"] == 0


def test_bad_inputs(client):
    assert post_archive(client, b"not an archive").status_code == 422
    assert post_archive(client, b"").status_code == 422
    assert client.post("/api/scan").status_code == 400


def test_zip_bomb_entry_skipped_and_total_capped():
    import pytest
    from vulnscope.adapters.outbound.archive_reader import ArchiveLimits, SafeArchiveReader
    from vulnscope.domain.errors import ArchiveError
    bomb = SafeArchiveReader().read(make_zip({"a.py": "A" * 3_000_000}))  # over per-file cap -> never inflated
    assert bomb.skipped_large == 1 and bomb.files[0].content is None
    many = make_zip({f"f{i}.py": ("x = %d\n" % i) * 400 for i in range(50)})
    with pytest.raises(ArchiveError):
        SafeArchiveReader(ArchiveLimits(max_total_bytes=20_000)).read(many)


def test_upload_too_large(tmp_path, ai):
    from vulnscope.adapters.inbound.http.app import create_app
    from vulnscope.bootstrap import build_container
    from vulnscope.config import Settings
    s = Settings(db_path=str(tmp_path / "x.db"), max_upload_mb=1, secret_key="k" * 40)
    s.finalize()
    cl = create_app(s, build_container(s, ai_client=ai)).test_client()
    assert post_archive(cl, b"PK\x03\x04" + b"0" * 2_000_000).status_code == 413


def test_ai_explain_and_fallback(client, ai):
    f = {"rule_id": "INJ001", "path": "a.py", "line": 3, "context": [{"n": 3, "text": "cur.execute('..' + x)", "hit": True}]}
    d = client.post("/api/ai/explain", json={"finding": f}).get_json()
    assert d["engine"] == "fake-ai" and d["text"] == "FAKE AI ANSWER" and not d["fallback"]
    assert "UNTRUSTED" in ai.calls[0][0]
    ai.fail = True
    d = client.post("/api/ai/explain", json={"finding": f}).get_json()
    assert d["fallback"] and "parameterised" in d["text"]
    assert client.post("/api/ai/explain", json={"finding": {"rule_id": "NOPE"}}).status_code == 404


def test_ai_never_receives_secrets(client, ai):
    f = {"rule_id": "SEC003", "path": "a.py", "line": 1,
         "context": [{"n": 1, "text": "password = 'SuperSecretValue123'", "hit": True}]}
    client.post("/api/ai/explain", json={"finding": f})
    assert "SuperSecretValue123" not in ai.calls[0][1]


def test_ai_summary(client):
    d = client.post("/api/ai/summary", json={"by_severity": {"high": 2}, "risk_score": 40,
                                             "top": [{"rule_id": "INJ001", "path": "a.py", "line": 1}]}).get_json()
    assert d["text"]


def test_rule_playbook(client):
    d = client.post("/api/playbook", json={"rule_id": "SEC003"}).get_json()
    assert d["simulation"] and any("iam" in s["code"] for s in d["steps"])
    assert client.post("/api/playbook", json={"rule_id": "zzz"}).status_code == 404


def test_markov_lifecycle(client, auth):
    d = client.get("/api/markov/lifecycle").get_json()
    assert d["data_source"] == "prior" and d["expected_steps_to_closed"]["abierta"] > 0
    assert d["expected_steps_to_closed"]["cerrada"] == 0
    assert all(abs(sum(row) - 1) < 1e-3 for row in d["matrix"])
    client.post("/api/vulnerabilidades", json=vuln(), headers=auth)
    assert client.get("/api/markov/lifecycle").get_json()["data_source"] == "history+prior"
    assert client.get("/api/markov/lifecycle?from=zz").status_code == 400


def test_security_headers_and_pages(client):
    for path in ("/", "/app", "/healthz", "/api"):
        r = client.get(path)
        assert r.status_code == 200, path
        h = r.headers
        assert "script-src 'self'" in h["Content-Security-Policy"] and "unsafe-inline" not in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    html = client.get("/").get_data(as_text=True) + client.get("/app").get_data(as_text=True)
    assert "<script>" not in html and " style=" not in html and " onclick=" not in html


def test_errors_are_json_and_generic(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.get_json()["error"] == "Not found"
    assert client.delete("/").status_code == 405


def test_rate_limit_login(client):
    codes = [client.post("/login", json={"username": "a", "clave": "b"}).status_code for _ in range(10)]
    assert 429 in codes


def test_account_lockout(client):
    from vulnscope.adapters.outbound.auth_adapters import ConfigAuthenticator
    from vulnscope.domain.errors import RateLimitedError
    from werkzeug.security import generate_password_hash
    import pytest
    a = ConfigAuthenticator("admin", generate_password_hash("pw"), max_failures=3)
    for _ in range(3):
        assert a.verify("admin", "bad") is False
    with pytest.raises(RateLimitedError):
        a.verify("admin", "pw")


def test_production_requires_secrets():
    from vulnscope.config import Settings
    import pytest
    with pytest.raises(RuntimeError):
        Settings(env="production").finalize()
    with pytest.raises(RuntimeError):
        Settings(env="production", secret_key="a" * 40, admin_password_hash="h").finalize()  # no allowed hosts
    Settings(env="production", secret_key="a" * 40, admin_password_hash="h", allowed_hosts=("x.com",)).finalize()


def test_host_header_enforced(tmp_path, ai):
    from vulnscope.adapters.inbound.http.app import create_app
    from vulnscope.bootstrap import build_container
    from vulnscope.config import Settings
    s = Settings(db_path=str(tmp_path / "h.db"), secret_key="k" * 40, allowed_hosts=("good.example",))
    s.finalize()
    cl = create_app(s, build_container(s, ai_client=ai)).test_client()
    assert cl.get("/healthz", headers={"Host": "evil.example"}).status_code == 400
    assert cl.get("/healthz", headers={"Host": "good.example"}).status_code == 200


def test_spanish_everywhere(client, ai, auth):
    from vulnscope.domain.rules import FILE_RULES, RULES
    es = client.get("/api/rule-text?lang=es").get_json()
    en = client.get("/api/rule-text?lang=en").get_json()
    assert len(es) == len(RULES) + len(FILE_RULES) + 1 == len(en)
    assert es["INJ001"]["title"].startswith("Consulta SQL") and en["INJ001"]["title"].startswith("SQL query")
    assert client.get("/api/rule-text?lang=xx").get_json()["INJ001"] == en["INJ001"]
    pb = client.post("/api/playbook", json={"rule_id": "SEC003", "lang": "es"}).get_json()
    assert "Rotar la credencial" in pb["steps"][-2]["label"] or any("Rotar" in s["label"] for s in pb["steps"])
    f = {"rule_id": "INJ001", "path": "a.py", "line": 3, "context": []}
    ai.fail = True
    d = client.post("/api/ai/explain", json={"finding": f, "lang": "es"}).get_json()
    assert "Cómo solucionarlo" in d["text"]
    d = client.post("/api/ai/summary", json={"risk_score": 5, "lang": "es"}).get_json()
    assert d["text"].startswith("Corrige")
    ai.fail = False
    client.post("/api/ai/explain", json={"finding": f, "lang": "es"})
    assert "Spanish" in ai.calls[-1][0]
    vid = client.post("/api/vulnerabilidades", json={"titulo": "x", "cve_codigo": "CVE-2024-1234", "severidad": "critica",
                                                     "estado": "abierta", "puntaje_cvss": 9}, headers=auth).get_json()["id"]
    assert client.get(f"/api/vulnerabilidades/{vid}/playbook?lang=es", headers=auth).get_json()["strategy"].startswith("AISLAMIENTO")
