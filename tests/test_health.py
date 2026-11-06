"""Tests de la Fase 0: la API levanta y /health responde."""

from fastapi.testclient import TestClient

from qrsandbox import __version__
from qrsandbox.api.main import app

cliente = TestClient(app)


def test_health_responde_ok():
    r = cliente.get("/health")
    assert r.status_code == 200
    assert r.json() == {"estado": "ok", "version": __version__}


def test_swagger_desactivado():
    # La UI de documentación no debe estar expuesta.
    assert cliente.get("/docs").status_code == 404
