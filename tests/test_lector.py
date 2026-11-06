"""Fase 1: el lector trata la salida del worker como dato tainted."""

import json

from qrsandbox.comun.esquemas import EvFin, EvNavegacion
from qrsandbox.orquestador.lector import LectorEventos


def linea(**ev) -> bytes:
    return (json.dumps(ev) + "\n").encode()


RESULTADO_OK = {
    "url_inicial": "https://example.com",
    "url_final": "https://example.com/",
    "cadena_redirecciones": ["https://example.com"],
    "titulo": "Example Domain",
    "estado_http": 200,
    "formularios_password": 0,
    "dominios_terceros": [],
    "n_dominios_terceros": 0,
    "tiempo_carga_ms": 300,
}


def test_eventos_validos_se_aceptan():
    lector = LectorEventos()
    evs = lector.alimentar(
        linea(tipo="navegacion", t_ms=10, url="https://example.com/")
        + linea(tipo="fin", t_ms=20, resultado=RESULTADO_OK)
    )
    assert [type(e) for e in evs] == [EvNavegacion, EvFin]
    assert lector.descartados == 0


def test_lineas_partidas_entre_chunks():
    lector = LectorEventos()
    datos = linea(tipo="navegacion", t_ms=10, url="https://example.com/")
    assert lector.alimentar(datos[:7]) == []
    assert len(lector.alimentar(datos[7:])) == 1


def test_json_malformado_y_tipo_desconocido_se_descartan():
    lector = LectorEventos()
    evs = lector.alimentar(
        b"{no es json\n"
        + linea(tipo="ejecutar_comando", t_ms=1, cmd="rm -rf /")
        + linea(tipo="navegacion", t_ms=1, url="https://ok.cl/", extra="campo no previsto")
        + linea(tipo="navegacion", t_ms="1", url="https://ok.cl/")  # tipo incorrecto (strict)
    )
    assert evs == []
    assert lector.descartados == 4


def test_urls_peligrosas_se_rechazan():
    lector = LectorEventos()
    for url in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "https://a\r\nb.cl"]:
        lector.alimentar(linea(tipo="navegacion", t_ms=1, url=url))
    assert lector.descartados == 4


def test_linea_gigante_se_descarta_sin_guardarla():
    lector = LectorEventos(max_linea=1000)
    gigante = b'{"tipo":"error","t_ms":1,"mensaje":"' + b"A" * 5000 + b'"}\n'
    evs = lector.alimentar(gigante + linea(tipo="navegacion", t_ms=2, url="https://ok.cl/"))
    assert len(evs) == 1  # la línea siguiente sigue procesándose
    assert lector.descartados == 1
    assert len(lector._buffer) == 0


def test_salida_total_excesiva_marca_excedido():
    lector = LectorEventos(max_total=10_000)
    for _ in range(200):  # ~13 KB > 10 KB
        lector.alimentar(linea(tipo="request_tercero", t_ms=1, dominio="ads.example"))
    assert lector.excedido


def test_demasiados_eventos_marca_excedido():
    lector = LectorEventos(max_eventos=5)
    lector.alimentar(linea(tipo="request_tercero", t_ms=1, dominio="a.cl") * 10)
    assert lector.excedido


def test_cerrar_procesa_ultima_linea_sin_salto():
    lector = LectorEventos()
    lector.alimentar(json.dumps({"tipo": "error", "t_ms": 1, "mensaje": "x"}).encode())
    assert len(lector.cerrar()) == 1
