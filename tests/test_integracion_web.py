"""Fase 5 (aceptación): en un Chromium real, un <title> malicioso del sitio analizado se
muestra como texto y no se ejecuta; las páginas cargan sin violar la CSP ni dar errores.

El navegador corre dentro de la imagen del worker (ya trae Chromium) con --network host,
contra la app servida en este proceso con un orquestador simulado.
"""

import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

docker = pytest.importorskip("docker")

from qrsandbox.api import analisis as A
from qrsandbox.api import main
from qrsandbox.api.log import obtener_log
from qrsandbox.tlog.log import LogTransparencia

from .test_api_analisis import TITULO_MALICIOSO, lineas

pytestmark = pytest.mark.integracion
NAVEGADOR = Path(__file__).resolve().parent / "navegador"


def puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def servidor(tmp_path, monkeypatch):
    log = LogTransparencia(tmp_path / "t.sqlite", Ed25519PrivateKey.generate())
    main.app.dependency_overrides[obtener_log] = lambda: log
    extra = [{"tipo": "navegacion", "t_ms": 3, "url": "https://example.com/<script>alert(1)</script>"},
             {"tipo": "error", "t_ms": 4, "mensaje": "<img src=x onerror=window.__xss=1>"}]
    monkeypatch.setattr(A, "flujo_orquestador",
                        lambda url: iter(lineas(url, titulo=TITULO_MALICIOSO, extra=extra)))
    puerto = puerto_libre()
    srv = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=puerto, log_level="warning"))
    hilo = threading.Thread(target=srv.run, daemon=True)
    hilo.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{puerto}"
    srv.should_exit = True
    hilo.join(5)
    main.app.dependency_overrides.clear()


def test_titulo_malicioso_no_se_ejecuta_en_el_navegador(servidor):
    cliente = docker.from_env()
    try:
        cliente.images.get("qrsandbox-worker:dev")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"falta la imagen del worker: {e}")
    r = httpx.post(f"{servidor}/analisis", json={"url": "https://example.com"},
                   headers={"X-QRSandbox-CSRF": "1"})
    assert r.status_code == 202
    id_analisis = r.json()["id"]

    salida = cliente.containers.run(
        "qrsandbox-worker:dev", ["/navegador/xss.py", servidor, id_analisis],
        entrypoint="python", network_mode="host", remove=True,
        volumes={str(NAVEGADOR): {"bind": "/navegador", "mode": "ro"}},
    ).decode()
    datos = json.loads(salida.strip().splitlines()[-1])

    a = datos["paginas"][f"/analisis/{id_analisis}"]
    assert a["xss"] == "undefined", "¡el script del título se ejecutó!"
    assert a["titulo_mostrado"] == TITULO_MALICIOSO  # se ve literal, como texto
    assert a["imgs_inyectadas"] == 0
    assert "<script>alert(1)</script>" in a["linea"]  # la URL hostil también se ve como texto
    assert a["dialogos"] == []
    assert a["pantalla_src"].startswith(("blob:", "/analisis/"))  # frame o captura final
    assert a["veredicto"].startswith("Sin alertas")
    for ruta, p in datos["paginas"].items():
        assert p["csp"] == [], f"violación de CSP en {ruta}: {p['csp']}"
        assert p["errores"] == [], f"error de JS en {ruta}: {p['errores']}"


def test_flujo_completo_del_comercio_en_el_navegador(servidor, monkeypatch):
    """Registrar -> escanear en ese lugar (verificado en el navegador) -> explorar -> revocar."""
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(lineas(url)))
    salida = docker.from_env().containers.run(
        "qrsandbox-worker:dev", ["/navegador/flujo_comercio.py", servidor],
        entrypoint="python", network_mode="host", remove=True,
        volumes={str(NAVEGADOR): {"bind": "/navegador", "mode": "ro"}},
    ).decode()
    r = json.loads(salida.strip().splitlines()[-1])
    assert r["errores"] == []
    assert r["registro"].startswith("✔ Registrado como entrada #0"), r["registro"]
    assert "verificado en tu navegador" in r["registro"]
    assert r["canvas_qr"] == 1 and "activo" in r["mis_qrs"]
    lat, lon = (float(x) for x in r["coordenadas"].split(","))
    assert abs(lat - -33.4378) < 0.001 and abs(lon - -70.6505) < 0.001
    assert "✅ Verificado" in r["log"] and "✔ Comprobado en tu navegador" in r["log"]
    assert "✔ Firma del log verificada" in r["sth"]
    assert "✔ en el árbol" in r["verificacion_fila"] and "✔ firma" in r["verificacion_fila"]
    assert r["consistencia"].startswith("✔")
    # Segunda visita al explorador: comprueba sola que el log solo creció (1 -> 2).
    assert "solo creció (1 → 2 entradas)" in r["sth_despues"]
    assert "revocado" in r["revocacion"] and "revocado" in r["mis_qrs_despues"]
