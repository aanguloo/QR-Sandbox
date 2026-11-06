"""Fase 3: endpoints /log/... y auditor (contra la API real, sin red)."""

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from qrsandbox.api import log as api_log
from qrsandbox.api.main import app
from qrsandbox.tlog import merkle
from qrsandbox.tlog.auditor import auditar, verificar_entre
from qrsandbox.tlog.log import LogTransparencia
from qrsandbox.tlog.registro import firmar_registro

from .test_tlog import adulterar_hoja

LAT, LON = -33.4378, -70.6505


@pytest.fixture
def clave_log():
    return Ed25519PrivateKey.generate()


def nuevo_log(tmp_path, clave_log, nombre="tlog.sqlite"):
    return LogTransparencia(tmp_path / nombre, clave_log)


@pytest.fixture
def cliente(tmp_path, clave_log):
    log = nuevo_log(tmp_path, clave_log)
    app.dependency_overrides[api_log.obtener_log] = lambda: log
    yield TestClient(app)
    app.dependency_overrides.clear()


def usar_log(log):
    app.dependency_overrides[api_log.obtener_log] = lambda: log


def cuerpo(clave, url="https://pagos.ejemplo.cl/mesa/4", lat=LAT, lon=LON, radio=30):
    s = firmar_registro(
        clave, url_destino=url, lat_e6=round(lat * 1e6), lon_e6=round(lon * 1e6),
        radio_m=radio, descripcion="Carta QR", timestamp=int(time.time()),
    )
    return s.model_dump()


def registrar_n(cliente, n, prefijo="comercio"):
    for i in range(n):
        r = cliente.post("/log/registros", json=cuerpo(Ed25519PrivateKey.generate(),
                                                        url=f"https://{prefijo}{i}.cl/", lat=LAT + i))
        assert r.status_code == 201, r.text


# ------------------------------------------------------------------ endpoints


def test_registrar_y_verificar_recibo(cliente):
    r = cliente.post("/log/registros", json=cuerpo(Ed25519PrivateKey.generate()))
    assert r.status_code == 201
    recibo = r.json()
    sth = cliente.get("/log/sth").json()
    assert sth == recibo["sth"]
    hoja = merkle.hash_hoja(recibo["hoja"].encode())
    ruta = [bytes.fromhex(h) for h in recibo["prueba_inclusion"]]
    assert merkle.verificar_inclusion(0, 1, hoja, ruta, bytes.fromhex(sth["raiz"]))


def test_firma_invalida_da_400(cliente):
    datos = cuerpo(Ed25519PrivateKey.generate())
    datos["firma"] = base64.b64encode(b"\x00" * 64).decode()
    r = cliente.post("/log/registros", json=datos)
    assert r.status_code == 400 and "firma" in r.json()["detail"]
    assert cliente.get("/log/sth").json()["tamano"] == 0


def test_esquema_invalido_da_422(cliente):
    datos = cuerpo(Ed25519PrivateKey.generate())
    datos["registro"]["radio_m"] = "30"  # strict: string no es int
    assert cliente.post("/log/registros", json=datos).status_code == 422


def test_pruebas_por_http(cliente):
    registrar_n(cliente, 7)
    sth3 = cliente.get("/log/sth/3").json()
    sth7 = cliente.get("/log/sth").json()
    c = cliente.get("/log/prueba-consistencia", params={"primero": 3, "segundo": 7}).json()
    assert merkle.verificar_consistencia(
        3, 7, bytes.fromhex(sth3["raiz"]), bytes.fromhex(sth7["raiz"]),
        [bytes.fromhex(h) for h in c["ruta"]],
    )
    i = cliente.get("/log/prueba-inclusion", params={"indice": 5, "tamano": 7}).json()
    hoja = merkle.hash_hoja(cliente.get("/log/registros/5").json()["hoja"].encode())
    assert merkle.verificar_inclusion(
        5, 7, hoja, [bytes.fromhex(h) for h in i["ruta"]], bytes.fromhex(sth7["raiz"])
    )
    assert cliente.get("/log/prueba-inclusion", params={"indice": 9, "tamano": 7}).status_code == 400
    assert cliente.get("/log/prueba-consistencia", params={"primero": 8, "segundo": 7}).status_code == 400
    assert len(cliente.get("/log/registros", params={"desde": 2, "limite": 3}).json()["entradas"]) == 3


def test_consultar_tres_estados(cliente):
    url = "https://pagos.ejemplo.cl/mesa/4"
    cliente.post("/log/registros", json=cuerpo(Ed25519PrivateKey.generate(), url=url))

    def consultar(u, lat=LAT, lon=LON):
        return cliente.post("/log/consultar", json={"url": u, "lat": lat, "lon": lon}).json()

    assert consultar(url)["estado"] == "verificado"
    assert consultar("https://pagos-ejemplo.xyz/mesa/4")["estado"] == "no_coincide"
    assert consultar(url, lat=LAT + 0.02)["estado"] == "sin_registro"
    assert cliente.post("/log/consultar", json={"url": url, "lat": 120, "lon": 0}).status_code == 422


def test_auditoria_por_clave(cliente):
    comercio = Ed25519PrivateKey.generate()
    c = cuerpo(comercio)
    cliente.post("/log/registros", json=c)
    registrar_n(cliente, 3)
    r = cliente.get("/log/por-clave", params={"clave": c["registro"]["clave_publica"]}).json()
    assert [e["indice"] for e in r["entradas"]] == [0]
    assert cliente.get("/log/por-clave", params={"clave": "corta"}).status_code == 422


# ------------------------------------------------------------------ auditor


def test_auditor_acepta_crecimiento_honesto(cliente):
    estado = {}
    registrar_n(cliente, 3)
    assert auditar(cliente, estado)["ok"]
    registrar_n(cliente, 4, prefijo="otro")
    informe = auditar(cliente, estado, completo=True)
    assert informe["ok"], informe
    assert estado["sth"]["tamano"] == 7
    assert verificar_entre(cliente, 2, 7, estado["clave_log"]) is None


def test_auditor_detecta_log_bifurcado(tmp_path, clave_log, cliente):
    """El operador (con la clave del log) muestra otra historia: firmas válidas, pero inconsistente."""
    estado = {}
    registrar_n(cliente, 3)
    assert auditar(cliente, estado)["ok"]

    otra_historia = nuevo_log(tmp_path, clave_log, "bifurcado.sqlite")
    usar_log(otra_historia)
    registrar_n(cliente, 4, prefijo="falso")
    informe = auditar(cliente, estado)
    assert not informe["ok"]
    assert "reescrito" in informe["alertas"][0]
    assert estado["sth"]["tamano"] == 3  # el estado no avanza tras una alerta


def test_auditor_detecta_log_que_se_achica(tmp_path, clave_log, cliente):
    estado = {}
    registrar_n(cliente, 3)
    auditar(cliente, estado)
    usar_log(nuevo_log(tmp_path, clave_log, "chico.sqlite"))  # misma clave, 1 entrada
    registrar_n(cliente, 1)
    informe = auditar(cliente, estado)
    assert not informe["ok"] and "achicó" in informe["alertas"][0]


def test_auditor_detecta_cambio_de_clave_del_log(tmp_path, cliente):
    estado = {}
    registrar_n(cliente, 3)
    auditar(cliente, estado)
    usar_log(nuevo_log(tmp_path, Ed25519PrivateKey.generate(), "otro.sqlite"))
    informe = auditar(cliente, estado)
    assert not informe["ok"]
    assert "clave" in informe["alertas"][0]


def test_auditor_completo_detecta_hoja_adulterada(tmp_path, cliente):
    estado = {}
    registrar_n(cliente, 5)
    assert auditar(cliente, estado, completo=True)["ok"]
    adulterar_hoja(tmp_path / "tlog.sqlite", 1, "https://phishing.example/")
    informe = auditar(cliente, {}, completo=True)
    assert not informe["ok"]
    assert any("raíz" in a for a in informe["alertas"])
    assert any("firma" in a for a in informe["alertas"])
