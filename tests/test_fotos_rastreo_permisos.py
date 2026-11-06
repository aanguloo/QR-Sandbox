"""Fase 6: fotos paso a paso, rastreadores de IP, permisos sensibles y marcas nuevas."""

import json

from fastapi.testclient import TestClient

from qrsandbox.api import analisis as A
from qrsandbox.api import main
from qrsandbox.comun.esquemas import ADAPTADOR_EVENTO
from qrsandbox.senales import estaticas as E
from qrsandbox.senales.dinamicas import senales_dinamicas
from qrsandbox.senales.dominio import cargar_marcas, partes_host
from qrsandbox.veredicto.motor import evaluar

from .test_api_analisis import CSRF, entorno, jpeg, lineas  # noqa: F401 (fixture)
from .test_senales import analisis, codigos

cliente = TestClient(main.app, headers=CSRF)

# ------------------------------------------------------------------ fotos paso a paso


def _frame(t_ms):
    import base64

    return {"tipo": "captura", "t_ms": t_ms, "jpeg_b64": base64.b64encode(jpeg()).decode()}


def test_fotos_en_momentos_clave(monkeypatch):
    url = "https://example.com"
    extra = [_frame(10), {"tipo": "redireccion", "t_ms": 20, "desde": url, "hacia": "https://otro.cl/"},
             _frame(30), {"tipo": "navegacion", "t_ms": 40, "url": "https://otro.cl/"}, _frame(50)]
    monkeypatch.setattr(A, "flujo_orquestador", lambda u: iter(lineas(u, extra=extra)))
    r = cliente.post("/analisis?esperar=true", json={"url": url}).json()
    etiquetas = [f["etiqueta"] for f in r["fotos"]]
    assert etiquetas[0] == "Primera imagen"
    assert "Redirigiendo a otro.cl" in etiquetas
    # La captura final es la misma imagen que la última foto: se marca, no se duplica.
    assert etiquetas[-1] == "Llegó a otro.cl · captura final"
    foto = cliente.get(r["fotos"][1]["url"])
    assert foto.headers["content-type"] == "image/jpeg" and foto.content.startswith(b"\xff\xd8\xff")
    assert cliente.get(r["fotos"][0]["url"].replace("/0", "/99")).status_code == 404


def test_fotos_acotadas_y_la_ultima_es_la_final():
    a = A.Analisis("a" * 32, "https://a.cl", None, None)
    for i in range(30):
        a.marcar_momento(f"paso {i}")
        a.poner_frame(jpeg(), i * 1000)
    a.foto_final(b"\xff\xd8\xff final")  # distinta de la última: ocupa el lugar reservado
    assert len(a.fotos) == A.MAX_FOTOS
    assert a.fotos[-1][1] == "Captura final"
    eventos_foto = [e for e in a.desde(0) if e.tipo == "foto"]
    assert len(eventos_foto) == A.MAX_FOTOS


def test_frames_seguidos_sin_novedad_no_se_guardan_todos():
    a = A.Analisis("b" * 32, "https://a.cl", None, None)
    for i in range(10):
        a.poner_frame(jpeg(), i * 100)  # 10 frames en 1 s, sin navegación
    assert len(a.fotos) == 1  # solo "Primera imagen" (el resto, por intervalo)


# ------------------------------------------------------------------ rastreadores de IP


def test_rastreador_en_el_enlace_inicial():
    assert codigos(E.senal_rastreador(partes_host("https://grabify.link/ABC123"))) == {"rastreador_ip"}
    assert codigos(E.senal_rastreador(partes_host("https://iplogger.org/2abc"))) == {"rastreador_ip"}
    assert E.senal_rastreador(partes_host("https://example.com/")) == []


def test_rastreador_escondido_detras_de_un_acortador():
    a = analisis(url_inicial="https://bit.ly/x", url_final="https://example.com/",
                 cadena_redirecciones=["https://bit.ly/x", "https://grabify.link/ABC", "https://example.com/"],
                 titulo="Example", formularios_password=0)
    assert "rastreador_ip" in codigos(senales_dinamicas(a))
    v = evaluar(E.analizar_url("https://bit.ly/x"), analisis=a)
    assert v["estado"] in ("sospechoso", "peligroso")
    assert "registra tu IP" in v["resumen"]


# ------------------------------------------------------------------ permisos


def test_evento_de_permiso_tiene_esquema_cerrado():
    ok = ADAPTADOR_EVENTO.validate_json(json.dumps({"tipo": "permiso_solicitado", "t_ms": 1, "permiso": "camara"}))
    assert ok.permiso == "camara"
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ADAPTADOR_EVENTO.validate_json(json.dumps({"tipo": "permiso_solicitado", "t_ms": 1, "permiso": "root"}))


def test_permiso_sensible():
    a = analisis(titulo="x", formularios_password=0, url_final="https://bit.ly/x",
                 cadena_redirecciones=["https://bit.ly/x"], permisos=["geolocalizacion", "camara"])
    h = {x.codigo: x for x in senales_dinamicas(a)}
    assert "permiso_sensible" in h
    assert "tu ubicación y la cámara" in h["permiso_sensible"].razon


# ------------------------------------------------------------------ marcas nuevas


def test_marcas_que_faltaban():
    marcas = cargar_marcas()
    for url, marca in [("https://docusign-firmar.xyz/", "DocuSign"),
                       ("https://westernunion-envios.com/", "Western Union"),
                       ("https://www.roblox.ly/", "Roblox")]:
        h = E.senal_marca(partes_host(url), marcas)
        assert h and marca in h[0].razon, url
    assert E.senal_marca(partes_host("https://www.docusign.com/"), marcas) == []
