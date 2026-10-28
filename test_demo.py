"""Pruebas de la demo: confirman que cada escenario muestra la diferencia esperada."""
import pytest
from fastapi.testclient import TestClient
import main


@pytest.fixture()
def c():
    with TestClient(main.app, raise_server_exceptions=False) as client:
        client.post("/vulnerable/reset"); client.post("/secure/reset")
        yield client


def total(c, m):
    return c.get(f"/{m}/accounts").json()["total"]


def saldo(c, m, cid):
    return {x["id"]: x["saldo"] for x in c.get(f"/{m}/accounts").json()["cuentas"]}[cid]


T = {"origen": "ANA", "destino": "BETO", "monto": 200, "caida_a_mitad": False}


def test_normal_ambas_ok(c):
    for m in ("vulnerable", "secure"):
        assert c.post(f"/{m}/transfer", json=T).status_code == 200
        assert total(c, m) == 3000 and saldo(c, m, "ANA") == 800 and saldo(c, m, "BETO") == 1200


def test_caida_vulnerable_pierde_dinero_y_filtra(c):
    r = c.post("/vulnerable/transfer", json={**T, "caida_a_mitad": True})
    assert r.status_code == 500
    body = r.json()
    assert "traceback" in body and "sql" in body and "base_de_datos" in body   # CWE-209
    assert total(c, "vulnerable") == 2800                                       # se perdieron $200
    assert c.get("/vulnerable/audit").json()["eventos"] == []                   # nadie se enteró (A09)


def test_caida_segura_hace_rollback_y_alerta(c):
    r = c.post("/secure/transfer", json={**T, "caida_a_mitad": True})
    assert r.status_code == 500
    body = r.json()
    assert set(body) == {"ok", "error", "error_id"} and "Traceback" not in str(body)
    assert total(c, "secure") == 3000 and saldo(c, "secure", "ANA") == 1000
    ev = c.get("/secure/audit").json()["eventos"]
    assert ev[0]["evento"] == "ERROR_INTERNO" and ev[0]["error_id"] == body["error_id"]


def test_destino_inexistente(c):
    bad = {**T, "destino": "ZZZ"}
    assert c.post("/vulnerable/transfer", json=bad).status_code == 500
    assert total(c, "vulnerable") == 2800
    r = c.post("/secure/transfer", json=bad)
    assert r.status_code == 422 and total(c, "secure") == 3000


def test_monto_negativo(c):
    neg = {**T, "monto": -500}
    assert c.post("/vulnerable/transfer", json=neg).status_code == 200      # roba a Beto
    assert saldo(c, "vulnerable", "BETO") == 500 and saldo(c, "vulnerable", "ANA") == 1500
    assert c.post("/secure/transfer", json=neg).status_code == 400
    assert saldo(c, "secure", "BETO") == 1000


def test_rafaga_rate_limit(c):
    p = {**T, "monto": 1}
    v = [c.post("/vulnerable/transfer", json=p).status_code for _ in range(30)]
    s = [c.post("/secure/transfer", json=p).status_code for _ in range(30)]
    assert v.count(200) == 30
    assert s.count(200) == main.RATE_LIMIT and s.count(429) == 30 - main.RATE_LIMIT
    assert any(e["evento"] == "ALERTA_RATE_LIMIT" for e in c.get("/secure/audit").json()["eventos"])


def test_audit_append_only(c):
    c.post("/secure/transfer", json=T)
    conn = main.connect("secure")
    with pytest.raises(Exception):
        conn.execute("DELETE FROM audit"); conn.commit()
    conn.close()


def test_index(c):
    assert c.get("/").status_code == 200
