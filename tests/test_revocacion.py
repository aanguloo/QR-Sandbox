"""Fase 5: revocación de QRs en el log."""

import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qrsandbox.tlog import merkle
from qrsandbox.tlog.auditor import auditar
from qrsandbox.tlog.log import LogTransparencia, RegistroRechazado, leer_entrada
from qrsandbox.tlog.registro import SolicitudRevocacion, firmar, firmar_revocacion

from .test_tlog import AHORA, LAT, LON, Reloj, registro

URL = "https://pagos.ejemplo.cl/mesa/4"


@pytest.fixture
def log(tmp_path):
    return LogTransparencia(tmp_path / "t.sqlite", Ed25519PrivateKey.generate(), reloj=Reloj())


def revocacion(clave, indice, motivo="Cambiamos de proveedor de pagos", t=AHORA):
    return firmar_revocacion(clave, indice=indice, motivo=motivo, timestamp=t)


def test_revocar_quita_la_verificacion_y_queda_en_el_log(log):
    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    assert log.consultar(URL, LAT, LON)["estado"] == "verificado"

    recibo = log.revocar(revocacion(comercio, 0))
    assert recibo["indice"] == 1 and recibo["sth"]["tamano"] == 2
    hoja = merkle.hash_hoja(recibo["hoja"].encode())
    ruta = [bytes.fromhex(h) for h in recibo["prueba_inclusion"]]
    assert merkle.verificar_inclusion(1, 2, hoja, ruta, bytes.fromhex(recibo["sth"]["raiz"]))

    c = log.consultar(URL, LAT, LON)
    assert c["estado"] == "sin_registro"
    assert [e["indice"] for e in c["revocados_cercanos"]] == [0]
    # Tampoco dispara "no coincide" con otro destino.
    assert log.consultar("https://otro.cl/", LAT, LON)["estado"] == "sin_registro"
    tipo, modelo, _, _ = leer_entrada(log.entrada(1)["hoja"])
    assert tipo == "revocacion" and modelo.indice == 0


def test_no_se_puede_revocar_el_qr_de_otro_comercio(log):
    """Adversario C: con su propia clave (firma válida) intenta retirar un QR ajeno."""
    comercio, atacante = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    with pytest.raises(RegistroRechazado, match="solo la clave que registró"):
        log.revocar(revocacion(atacante, 0))
    assert log.tamano() == 1


def test_revocacion_con_firma_invalida_o_vieja(log):
    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    s = revocacion(comercio, 0)
    falsa = SolicitudRevocacion(revocacion=s.revocacion, firma=firmar(comercio, b"otra"))
    with pytest.raises(RegistroRechazado, match="firma"):
        log.revocar(falsa)
    with pytest.raises(RegistroRechazado, match="timestamp"):
        log.revocar(revocacion(comercio, 0, t=AHORA - 3600))


def test_no_se_revoca_dos_veces_ni_algo_inexistente_ni_una_revocacion(log):
    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    log.revocar(revocacion(comercio, 0))
    with pytest.raises(RegistroRechazado, match="ya está revocado"):
        log.revocar(revocacion(comercio, 0, motivo="otra vez"))
    with pytest.raises(RegistroRechazado, match="no existe"):
        log.revocar(revocacion(comercio, 99))
    with pytest.raises(RegistroRechazado, match="solo se pueden revocar registros"):
        log.revocar(revocacion(comercio, 1))


def test_tras_revocar_se_puede_volver_a_registrar_con_una_firma_nueva(log):
    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    log.revocar(revocacion(comercio, 0))
    log.agregar(registro(comercio, url=URL, timestamp=AHORA + 1))  # nueva solicitud firmada
    assert log.consultar(URL, LAT, LON)["estado"] == "verificado"


def test_replay_de_un_registro_revocado_se_rechaza(log):
    """Atacante guardó la solicitud firmada original y la reenvía tras la revocación."""
    comercio = Ed25519PrivateKey.generate()
    original = registro(comercio, url=URL)
    log.agregar(original)
    log.revocar(revocacion(comercio, 0))
    with pytest.raises(RegistroRechazado, match="repetido"):
        log.agregar(original)
    assert log.consultar(URL, LAT, LON)["estado"] == "sin_registro"


def test_auditor_verifica_revocaciones(log, tmp_path):
    from fastapi.testclient import TestClient

    from qrsandbox.api import log as api_log
    from qrsandbox.api.main import app

    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    log.revocar(revocacion(comercio, 0))
    app.dependency_overrides[api_log.obtener_log] = lambda: log
    try:
        informe = auditar(TestClient(app), {}, completo=True)
    finally:
        app.dependency_overrides.clear()
    assert informe["ok"], informe


def test_migracion_de_un_log_de_la_fase_3(tmp_path):
    """El volumen real tiene un log creado antes de que existieran las revocaciones."""
    ruta = tmp_path / "viejo.sqlite"
    clave = Ed25519PrivateKey.generate()
    con = sqlite3.connect(ruta)
    con.executescript("""
        CREATE TABLE hojas (indice INTEGER PRIMARY KEY, datos BLOB NOT NULL, hash BLOB NOT NULL UNIQUE,
            clave_publica TEXT NOT NULL, url TEXT NOT NULL, lat_e6 INTEGER NOT NULL,
            lon_e6 INTEGER NOT NULL, radio_m INTEGER NOT NULL, t_log_ms INTEGER NOT NULL);
    """)
    con.close()
    log = LogTransparencia(ruta, clave, reloj=Reloj())
    comercio = Ed25519PrivateKey.generate()
    log.agregar(registro(comercio, url=URL))
    log.revocar(revocacion(comercio, 0))
    assert log.verificar_integridad()[0]
