"""Fase 3 (aceptación): QR Transparency Log."""

import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from qrsandbox.tlog import merkle
from qrsandbox.tlog.log import (
    LogTransparencia,
    RegistroRechazado,
    cargar_o_crear_clave,
    leer_hoja,
    misma_url,
)
from qrsandbox.tlog.registro import (
    Registro,
    SolicitudRegistro,
    firmar,
    firmar_registro,
    mensaje_sth,
    verificar_firma,
)

AHORA = 1_794_000_000  # reloj fijo para los tests
# Plaza de Armas de Santiago y alrededores.
LAT, LON = -33.437_800, -70.650_500


class Reloj:
    def __init__(self, t=AHORA):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clave_log():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def log(tmp_path, clave_log):
    return LogTransparencia(tmp_path / "tlog.sqlite", clave_log, reloj=Reloj())


@pytest.fixture
def comercio():
    return Ed25519PrivateKey.generate()


def registro(clave, url="https://pagos.ejemplo.cl/mesa/4", lat=LAT, lon=LON, radio=30, **kw):
    return firmar_registro(
        clave,
        url_destino=url,
        lat_e6=round(lat * 1e6),
        lon_e6=round(lon * 1e6),
        radio_m=radio,
        descripcion=kw.pop("descripcion", "Carta QR mesa 4"),
        timestamp=kw.pop("timestamp", AHORA),
    )


# ------------------------------------------------------------- registro y firmas


def test_registro_valido_devuelve_recibo_verificable(log, comercio, clave_log):
    recibo = log.agregar(registro(comercio))
    sth = recibo["sth"]
    assert recibo["indice"] == 0 and sth["tamano"] == 1
    # El recibo se verifica sin confiar en el servidor:
    hoja = merkle.hash_hoja(recibo["hoja"].encode())
    ruta = [bytes.fromhex(h) for h in recibo["prueba_inclusion"]]
    assert merkle.verificar_inclusion(0, 1, hoja, ruta, bytes.fromhex(sth["raiz"]))
    msg = mensaje_sth(sth["tamano"], bytes.fromhex(sth["raiz"]), sth["timestamp_ms"])
    assert verificar_firma(recibo["clave_log"], msg, sth["firma"])


def test_firma_invalida_se_rechaza(log, comercio):
    s = registro(comercio)
    falsa = SolicitudRegistro(registro=s.registro, firma=firmar(comercio, b"otra cosa"))
    with pytest.raises(RegistroRechazado, match="firma"):
        log.agregar(falsa)
    assert log.tamano() == 0


def test_registro_alterado_despues_de_firmar_se_rechaza(log, comercio):
    s = registro(comercio)
    alterado = s.registro.model_copy(update={"url_destino": "https://malo.cl/pago"})
    with pytest.raises(RegistroRechazado, match="firma"):
        log.agregar(SolicitudRegistro(registro=alterado, firma=s.firma))


def test_no_se_puede_registrar_a_nombre_de_otra_clave(log, comercio):
    """Adversario C: firma con su clave pero declara la clave pública del comercio."""
    atacante = Ed25519PrivateKey.generate()
    s = registro(atacante)
    suplantado = s.registro.model_copy(update={"clave_publica": registro(comercio).registro.clave_publica})
    with pytest.raises(RegistroRechazado, match="firma"):
        log.agregar(SolicitudRegistro(registro=suplantado, firma=s.firma))


def test_timestamp_viejo_o_futuro_se_rechaza(log, comercio):
    for t in (AHORA - 3600, AHORA + 3600):
        with pytest.raises(RegistroRechazado, match="timestamp"):
            log.agregar(registro(comercio, timestamp=t))


def test_duplicado_se_rechaza(log, comercio):
    s = registro(comercio)
    log.agregar(s)
    with pytest.raises(RegistroRechazado, match="repetido"):  # misma solicitud firmada
        log.agregar(s)
    with pytest.raises(RegistroRechazado, match="duplicado"):  # mismo QR, firma nueva
        log.agregar(registro(comercio, timestamp=AHORA + 5))


@pytest.mark.parametrize(
    "cambio",
    [
        {"url_destino": "HTTPS://Pagos.Ejemplo.CL/x"},  # no normalizada
        {"url_destino": "javascript:alert(1)"},
        {"lat_e6": 91_000_000},
        {"radio_m": 5000},
        {"descripcion": "a\nb"},
        {"clave_publica": "no-es-base64"},
        {"v": "otra-version"},
        {"extra": 1},
    ],
)
def test_esquema_del_registro_es_estricto(comercio, cambio):
    base = registro(comercio).registro.model_dump()
    with pytest.raises(ValidationError):
        Registro.model_validate({**base, **cambio})


def test_formato_canonico_es_estable():
    """Los bytes firmados deben poder reproducirse en JavaScript (claves ordenadas, sin espacios)."""
    r = Registro(
        v="qrtlog-registro-v1", url_destino="https://a.cl/ñ", lat_e6=-33437800,
        lon_e6=-70650500, radio_m=30, descripcion="Café ☕", timestamp=1,
        clave_publica="A" * 43 + "=",
    )
    assert r.canonico() == (
        '{"clave_publica":"' + "A" * 43 + '=","descripcion":"Café ☕","lat_e6":-33437800,'
        '"lon_e6":-70650500,"radio_m":30,"timestamp":1,"url_destino":"https://a.cl/ñ",'
        '"v":"qrtlog-registro-v1"}'
    ).encode()


# ------------------------------------------------------------- pruebas sobre el log


def poblar(log, n):
    claves = [Ed25519PrivateKey.generate() for _ in range(n)]
    for i, c in enumerate(claves):
        log.agregar(registro(c, url=f"https://comercio{i}.cl/", lat=LAT + i * 0.01))
    return claves


def test_inclusion_y_consistencia_en_el_log(log):
    poblar(log, 13)
    sths = {s.tamano: s for s in log.sths()}
    assert sorted(sths) == list(range(14))  # un STH firmado por cada tamaño, desde 0
    for n in (1, 5, 8, 13):
        for i in range(n):
            hoja = merkle.hash_hoja(log.entrada(i)["hoja"].encode())
            assert merkle.verificar_inclusion(i, n, hoja, log.prueba_inclusion(i, n), sths[n].raiz)
    for m, n in [(1, 13), (4, 13), (7, 8), (8, 13), (13, 13)]:
        prueba = log.prueba_consistencia(m, n)
        assert merkle.verificar_consistencia(m, n, sths[m].raiz, sths[n].raiz, prueba)


def test_triggers_impiden_modificar_y_borrar(log, tmp_path):
    poblar(log, 2)
    con = sqlite3.connect(tmp_path / "tlog.sqlite")
    for sql in ("UPDATE hojas SET url = 'x'", "DELETE FROM hojas", "DELETE FROM sths"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            con.execute(sql)
    con.close()


def adulterar_hoja(ruta_db, indice, nueva_url):
    """Atacante con acceso a la BD: quita el trigger y reescribe una hoja."""
    con = sqlite3.connect(ruta_db)
    datos = json.loads(con.execute("SELECT datos FROM hojas WHERE indice = ?", (indice,)).fetchone()[0])
    datos["registro"]["url_destino"] = nueva_url
    nuevos = json.dumps(datos, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    con.execute("DROP TRIGGER hojas_sin_update")
    con.execute("UPDATE hojas SET datos = ?, url = ? WHERE indice = ?", (nuevos, nueva_url, indice))
    con.commit()
    con.close()


def test_hoja_modificada_en_la_bd_hace_fallar_la_verificacion(log, tmp_path, clave_log):
    poblar(log, 6)
    sth = log.sth()
    assert log.verificar_integridad()[0]

    adulterar_hoja(tmp_path / "tlog.sqlite", 2, "https://phishing.example/pago")

    # 1) El log recalcula desde los datos crudos y detecta que no calza con sus STHs.
    ok, detalle = log.verificar_integridad()
    assert not ok and "no coincide" in detalle
    # 2) Un cliente que pide la prueba de inclusión de esa hoja no la puede verificar
    #    contra la raíz firmada.
    hoja = merkle.hash_hoja(log.entrada(2)["hoja"].encode())
    assert not merkle.verificar_inclusion(2, 6, hoja, log.prueba_inclusion(2, 6), sth.raiz)
    # 3) La hoja alterada tampoco tiene una firma válida del comercio.
    r, firma, _ = leer_hoja(log.entrada(2)["hoja"])
    assert not verificar_firma(r.clave_publica, r.canonico(), firma)


def test_reinicio_conserva_el_log(tmp_path, clave_log, comercio):
    a = LogTransparencia(tmp_path / "x.sqlite", clave_log, reloj=Reloj())
    a.agregar(registro(comercio))
    b = LogTransparencia(tmp_path / "x.sqlite", clave_log, reloj=Reloj())
    assert b.tamano() == 1 and b.sth().tamano == 1 and b.verificar_integridad()[0]


def test_clave_del_log_se_crea_con_permisos_0600(tmp_path):
    ruta = tmp_path / "clave.pem"
    c1 = cargar_o_crear_clave(ruta)
    assert oct(ruta.stat().st_mode & 0o777) == "0o600"
    c2 = cargar_o_crear_clave(ruta)
    assert c1.public_key().public_bytes_raw() == c2.public_key().public_bytes_raw()


# ------------------------------------------------------------- consulta al escanear


def test_consulta_verificado_no_coincide_y_sin_registro(log, comercio):
    url = "https://pagos.ejemplo.cl/mesa/4"
    log.agregar(registro(comercio, url=url, radio=30))

    r = log.consultar(url, LAT + 0.0002, LON)  # ~22 m del QR registrado
    assert r["estado"] == "verificado"
    c = r["coincidencias"][0]
    hoja = merkle.hash_hoja(c["hoja"].encode())
    ruta = [bytes.fromhex(h) for h in c["prueba_inclusion"]]
    assert merkle.verificar_inclusion(c["indice"], r["sth"]["tamano"], hoja, ruta, bytes.fromhex(r["sth"]["raiz"]))

    # Sticker superpuesto: mismo lugar, otro destino.
    r = log.consultar("https://pagos-ejemplo.xyz/mesa/4", LAT, LON)
    assert r["estado"] == "no_coincide"
    assert leer_hoja(r["otros_destinos_cercanos"][0]["hoja"])[0].url_destino == url

    # Lejos (~1,1 km): no hay registro.
    assert log.consultar(url, LAT + 0.01, LON)["estado"] == "sin_registro"


def test_consulta_redondea_la_ubicacion(log):
    r = log.consultar("https://a.cl/", -33.4378123456, -70.6505987654)
    assert r["ubicacion_usada"] == {"lat": -33.438, "lon": -70.651}


def test_misma_url():
    assert misma_url("https://a.cl", "https://a.cl/")
    assert misma_url("HTTPS://A.cl:443/x#frag", "https://a.cl/x")
    assert not misma_url("https://a.cl/x", "https://a.cl/y")
    assert not misma_url("http://a.cl/", "https://a.cl/")
    assert misma_url("https://a.cl?x=1", "https://a.cl/?x=1")
