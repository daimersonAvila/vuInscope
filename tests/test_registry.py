import pytest
from conftest import vuln


def test_login_ok_and_bad(client):
    assert "token" in client.post("/login", json={"username": "admin", "clave": "demo123"}).get_json()
    r = client.post("/login", json={"username": "admin", "clave": "nope"})
    assert r.status_code == 401 and "error" in r.get_json()
    assert client.post("/login", json={"username": "admin"}).status_code == 400
    assert client.post("/login", data="hola").status_code == 400


def test_writes_need_token(client):
    assert client.post("/api/vulnerabilidades", json=vuln()).status_code == 401
    assert client.post("/api/vulnerabilidades", json=vuln(), headers={"Authorization": "Bearer x.y.z"}).status_code == 401


def test_crud_flow(client, auth):
    r = client.post("/api/vulnerabilidades", json=vuln(), headers=auth)
    assert r.status_code == 201
    vid = r.get_json()["id"]
    assert client.get(f"/api/vulnerabilidades/{vid}").get_json()["cve_codigo"] == "CVE-2024-12345"
    assert client.put(f"/api/vulnerabilidades/{vid}", json=vuln(estado="mitigada"), headers=auth).status_code == 200
    assert client.get(f"/api/vulnerabilidades/{vid}").get_json()["estado"] == "mitigada"
    assert client.delete(f"/api/vulnerabilidades/{vid}", headers=auth).status_code == 200
    assert client.get(f"/api/vulnerabilidades/{vid}").status_code == 404


@pytest.mark.parametrize("change", [
    {"titulo": ""}, {"cve_codigo": "XYZ"}, {"severidad": "enorme"}, {"estado": "x"},
    {"puntaje_cvss": 11}, {"puntaje_cvss": -1}, {"puntaje_cvss": True}, {"puntaje_cvss": "8"},
    {"titulo": "x" * 201}])
def test_invalid_400(client, auth, change):
    assert client.post("/api/vulnerabilidades", json=vuln(**change), headers=auth).status_code == 400


def test_nan_score_rejected(client, auth):
    r = client.post("/api/vulnerabilidades", data='{"titulo":"a","cve_codigo":"CVE-2024-1234","severidad":"alta","estado":"abierta","puntaje_cvss":NaN}',
                    headers={**auth, "Content-Type": "application/json"})
    assert r.status_code == 400


def test_exact_duplicate_blocked(client, auth):
    assert client.post("/api/vulnerabilidades", json=vuln(), headers=auth).status_code == 201
    r = client.post("/api/vulnerabilidades", json=vuln(titulo="  SQL Injection en login  "), headers=auth)
    assert r.status_code == 409
    body = r.get_json()
    assert body["code"] == "duplicate_vulnerability" and body["existing_id"] == 1
    assert len(client.get("/api/vulnerabilidades").get_json()) == 1


def test_not_exact_is_allowed(client, auth):
    client.post("/api/vulnerabilidades", json=vuln(), headers=auth)
    for change in ({"puntaje_cvss": 8.2}, {"estado": "cerrada"}, {"titulo": "sql injection en login"}):
        assert client.post("/api/vulnerabilidades", json=vuln(**change), headers=auth).status_code == 201


def test_update_into_duplicate_blocked(client, auth):
    client.post("/api/vulnerabilidades", json=vuln(), headers=auth)
    vid = client.post("/api/vulnerabilidades", json=vuln(estado="cerrada"), headers=auth).get_json()["id"]
    assert client.put(f"/api/vulnerabilidades/{vid}", json=vuln(), headers=auth).status_code == 409


def test_bulk_register_skips_duplicates(client, auth):
    f = {"rule_id": "INJ001", "path": "app.py", "line": 12}
    r1 = client.post("/api/vulnerabilidades/bulk", json={"findings": [f, f, {"rule_id": "BAD"}]}, headers=auth).get_json()
    assert r1 == {"created": 1, "duplicates": 1, "invalid": 1}
    r2 = client.post("/api/vulnerabilidades/bulk", json={"findings": [f]}, headers=auth).get_json()
    assert r2["created"] == 0 and r2["duplicates"] == 1


def test_registry_playbook(client, auth):
    vid = client.post("/api/vulnerabilidades", json=vuln(severidad="critica"), headers=auth).get_json()["id"]
    d = client.get(f"/api/vulnerabilidades/{vid}/playbook", headers=auth).get_json()
    assert d["simulation"] and d["strategy"].startswith("IMMEDIATE ISOLATION") and "CVE-2024-12345" in d["steps"][0]["code"]
    client.put(f"/api/vulnerabilidades/{vid}", json=vuln(severidad="critica", estado="cerrada"), headers=auth)
    assert client.get(f"/api/vulnerabilidades/{vid}/playbook", headers=auth).get_json()["pending_action"] is False


def test_sql_injection_in_path_is_harmless(client):
    assert client.get("/api/vulnerabilidades/1;DROP TABLE x").status_code == 404
