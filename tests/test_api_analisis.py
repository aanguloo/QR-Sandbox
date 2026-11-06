"""Fase 1: endpoints de análisis de la API (orquestador simulado)."""

import base64

import pytest
from fastapi.testclient import TestClient

from qrsandbox.api import main

cliente = TestClient(main.app)
JPEG = b"\xff\xd8\xff\xe0" + b"0" * 100


def respuesta_falsa(url: str) -> dict:
    return {
        "id": "0123456789ab",
        "url": url,
        "runtime": "runc",
        "duracion_ms": 1500,
        "codigo_salida": 0,
        "timeout": False,
        "salida_excedida": False,
        "eventos": [{"tipo": "navegacion", "t_ms": 5, "url": url}],
        "eventos_descartados": 0,
        "resultado": None,
        "captura_jpeg_b64": base64.b64encode(JPEG).decode(),
        "contenedor_eliminado": True,
        "error": None,
    }


@pytest.fixture
def orquestador_falso(monkeypatch):
    monkeypatch.setattr(main, "pedir_analisis", respuesta_falsa)


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://x.cl", "no-es-url", "https://"]
)
def test_rechaza_urls_no_http(url, orquestador_falso):
    assert cliente.post("/analisis", json={"url": url}).status_code == 422


def test_rechaza_campos_extra(orquestador_falso):
    r = cliente.post("/analisis", json={"url": "https://example.com", "runtime": "privilegiado"})
    assert r.status_code == 422


def test_analisis_devuelve_resultado_y_captura(orquestador_falso):
    r = cliente.post("/analisis", json={"url": "https://example.com"})
    assert r.status_code == 200
    cuerpo = r.json()
    assert "captura_jpeg_b64" not in cuerpo
    assert cuerpo["contenedor_eliminado"] is True

    c = cliente.get(cuerpo["captura_url"])
    assert c.status_code == 200
    assert c.headers["content-type"] == "image/jpeg"
    assert c.headers["x-content-type-options"] == "nosniff"
    assert c.content == JPEG


def test_captura_con_id_invalido_da_404():
    assert cliente.get("/analisis/..%2f..%2fetc/captura").status_code == 404
    assert cliente.get("/analisis/zzzzzzzzzzzz/captura").status_code == 404


def test_orquestador_caido_da_503(monkeypatch):
    import httpx

    def caido(url):
        raise httpx.ConnectError("sin conexión")

    monkeypatch.setattr(main, "pedir_analisis", caido)
    assert cliente.post("/analisis", json={"url": "https://example.com"}).status_code == 503
