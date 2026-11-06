"""Fase 4 (aceptación): el veredicto tiene puntaje, estado y razones legibles."""

from datetime import UTC, datetime, timedelta

from qrsandbox.senales.estaticas import analizar_url
from qrsandbox.senales.hallazgos import PESOS
from qrsandbox.senales.red import InfoCertificado
from qrsandbox.veredicto.motor import evaluar, unir_es

from .test_senales import RedFalsa, analisis


def test_ejemplo_de_la_especificacion():
    """'Vas a login-micr0soft.xyz: usa un 0 en lugar de una o, el dominio y el certificado
    tienen 2 días, pasa por 4 redirecciones y muestra un formulario con la marca Microsoft.'"""
    ahora = datetime.now(UTC)
    cert = InfoCertificado(True, "Let's Encrypt", ahora - timedelta(days=1), ahora + timedelta(days=89))
    red = RedFalsa(2, cert)
    inicial = analizar_url("https://bit.ly/x", red=red)
    final = analizar_url("https://login-micr0soft.xyz/", red=red)
    v = evaluar(inicial, final, analisis())

    assert v["estado"] == "peligroso" and v["puntaje"] == 100
    assert v["destino"] == "login-micr0soft.xyz"
    assert v["resumen"].startswith("Vas a login-micr0soft.xyz: ")
    assert "un 0 en lugar de una o" in v["resumen"]
    assert "Microsoft" in v["resumen"]
    # Cada razón es legible y trae su peso; ordenadas de más a menos importante.
    pesos = [r["peso"] for r in v["razones"]]
    assert pesos == sorted(pesos, reverse=True)
    assert all(r["razon"].endswith(".") and len(r["razon"]) > 20 for r in v["razones"])
    assert {"sustitucion_marca", "dominio_muy_nuevo", "muchas_redirecciones",
            "password_con_marca_ajena"} <= {r["codigo"] for r in v["razones"]}


def test_sitio_legitimo_sin_alertas():
    v = evaluar(analizar_url("https://www.bancoestado.cl/", red=RedFalsa(9000)))
    assert v["estado"] == "sin_alertas" and v["puntaje"] == 0
    assert "no encontramos señales de riesgo" in v["resumen"]
    assert "solo se usaron señales estáticas" in v["resumen"]


def test_sospechoso_intermedio():
    v = evaluar(analizar_url("http://pago-rapido.xyz/cuenta"))  # sin https + TLD + palabra clave
    assert v["puntaje"] == PESOS["sin_https"] + PESOS["tld_riesgoso"] + PESOS["palabras_clave"] == 40
    assert v["estado"] == "sospechoso"


def consulta(estado, url_registrada="https://pagos.ejemplo.cl/mesa/4"):
    import json
    hoja = json.dumps({"registro": {"v": "qrtlog-registro-v1", "url_destino": url_registrada,
                       "lat_e6": 0, "lon_e6": 0, "radio_m": 30, "descripcion": "", "timestamp": 0,
                       "clave_publica": "A" * 43 + "="}, "firma": "x", "t_log_ms": 0})
    e = {"indice": 0, "hoja": hoja, "distancia_m": 10}
    return {"estado": estado, "coincidencias": [e] if estado == "verificado" else [],
            "otros_destinos_cercanos": [e] if estado == "no_coincide" else []}


def test_sticker_detectado_por_el_log_eleva_el_riesgo():
    """Un sitio sin señales propias, pero en un lugar con otro QR registrado."""
    v = evaluar(analizar_url("https://pagos-ejemplo.com/mesa/4"), consulta_log=consulta("no_coincide"))
    assert v["estado"] == "sospechoso" and v["puntaje"] == PESOS["log_no_coincide"]
    assert v["razones"][0]["codigo"] == "log_no_coincide"
    assert "https://pagos.ejemplo.cl/mesa/4" in v["razones"][0]["razon"]
    assert "sticker" in v["resumen"]


def test_qr_verificado_resta_y_se_menciona():
    v = evaluar(analizar_url("https://pagos.ejemplo.cl/mesa/4"), consulta_log=consulta("verificado"))
    assert v["puntaje"] == 0 and v["estado"] == "sin_alertas"
    assert "registrado por el comercio" in v["resumen"]


def test_verificado_no_tapa_un_phishing_evidente():
    """El log no es un pase libre: si el sitio es claramente malicioso, igual alerta."""
    v = evaluar(analizar_url("https://login-micr0soft.xyz/verify"), analisis=analisis(),
                consulta_log=consulta("verificado"))
    assert v["estado"] in ("sospechoso", "peligroso") and v["puntaje"] >= 70


def test_hallazgos_repetidos_cuentan_una_vez():
    a = analizar_url("https://a.xyz/")
    b = analizar_url("https://b.xyz/")
    v = evaluar(a, b)
    assert [r["codigo"] for r in v["razones"]] == ["tld_riesgoso"]


def test_unir_es():
    assert unir_es(["a"]) == "a"
    assert unir_es(["a", "b", "c"]) == "a, b y c"
