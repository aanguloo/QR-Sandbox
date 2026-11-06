"""Fase 1 (aceptación): analizar https://example.com con un worker real.

Requiere Docker, la imagen `qrsandbox-worker:dev` (`make build-worker`) e internet.
Correr con `make test-int`.
"""

import base64

import pytest

docker = pytest.importorskip("docker")

from qrsandbox.orquestador.ejecutor import ETIQUETA, ConfigWorker, ejecutar

pytestmark = pytest.mark.integracion


@pytest.fixture(scope="module")
def cliente():
    try:
        c = docker.from_env()
        c.images.get(ConfigWorker().imagen)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"Docker o imagen del worker no disponibles: {e}")
    return c


def test_example_com_devuelve_json_valido_y_contenedor_desaparece(cliente):
    r = ejecutar("https://example.com", cliente=cliente)

    assert r.error is None, r.error
    assert r.codigo_salida == 0
    assert r.resultado is not None
    assert r.resultado.titulo == "Example Domain"
    assert r.resultado.estado_http == 200
    assert r.resultado.url_final.startswith("https://example.com")
    assert r.eventos[-1]["tipo"] == "fin"
    assert r.eventos_descartados == 0

    assert r.captura_jpeg_b64
    assert base64.b64decode(r.captura_jpeg_b64).startswith(b"\xff\xd8\xff")

    # El contenedor desaparece al terminar.
    assert r.contenedor_eliminado
    assert cliente.containers.list(all=True, filters={"label": ETIQUETA}) == []


def test_url_inexistente_termina_con_error_controlado(cliente):
    r = ejecutar("https://no-existe.invalid", cliente=cliente)
    assert r.contenedor_eliminado
    assert any(e["tipo"] == "error" for e in r.eventos)
    assert r.eventos[-1]["tipo"] == "fin"
