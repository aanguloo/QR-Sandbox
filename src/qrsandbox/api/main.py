"""Aplicación FastAPI de QR-Sandbox (API pública).

La API NO tiene acceso a Docker: para analizar una URL le pide al orquestador,
por una red interna, que lo haga (interfaz estrecha: solo "analizar URL").
"""

import base64
import os
import re
from collections import OrderedDict
from threading import Lock

import httpx
from fastapi import FastAPI, HTTPException, Response
from pydantic import ValidationError

from qrsandbox import __version__
from qrsandbox.comun.esquemas import ResultadoAnalisis, SolicitudAnalisis

ORQUESTADOR_URL = os.environ.get("ORQUESTADOR_URL", "http://127.0.0.1:9000")
TIMEOUT_ORQUESTADOR_S = 45.0
MAX_CAPTURAS_EN_MEMORIA = 50
_ID_VALIDO = re.compile(r"^[0-9a-f]{12}$")

# docs_url/redoc_url desactivados: no exponemos la UI de Swagger (scripts de
# terceros desde CDN) en un servicio que se publicará por un túnel en la demo.
app = FastAPI(title="QR-Sandbox", version=__version__, docs_url=None, redoc_url=None)

# Fase 1: capturas en memoria (LRU acotado). La persistencia llega con SQLite.
_capturas: OrderedDict[str, bytes] = OrderedDict()
_lock_capturas = Lock()


def _guardar_captura(id_analisis: str, datos: bytes) -> None:
    with _lock_capturas:
        _capturas[id_analisis] = datos
        while len(_capturas) > MAX_CAPTURAS_EN_MEMORIA:
            _capturas.popitem(last=False)


def pedir_analisis(url: str) -> dict:
    """Llama al orquestador. Separado para poder simularlo en los tests."""
    r = httpx.post(f"{ORQUESTADOR_URL}/analizar", json={"url": url}, timeout=TIMEOUT_ORQUESTADOR_S)
    r.raise_for_status()
    return r.json()


@app.get("/health")
def health() -> dict[str, str]:
    """Chequeo de vida usado por el healthcheck de docker compose."""
    return {"estado": "ok", "version": __version__}


@app.post("/analisis")
def crear_analisis(solicitud: SolicitudAnalisis) -> dict:
    try:
        crudo = pedir_analisis(solicitud.url)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="orquestador no disponible") from None
    try:
        # El orquestador es de confianza, pero re-validamos su respuesta de todas formas:
        # es barato y evita que un bug allá se convierta en un bug acá.
        r = ResultadoAnalisis.model_validate(crudo)
    except ValidationError:
        raise HTTPException(status_code=502, detail="respuesta inválida del orquestador") from None

    salida = r.model_dump(mode="json", exclude={"captura_jpeg_b64"})
    salida["captura_url"] = None
    if r.captura_jpeg_b64:
        _guardar_captura(r.id, base64.b64decode(r.captura_jpeg_b64))
        salida["captura_url"] = f"/analisis/{r.id}/captura"
    return salida


@app.get("/analisis/{id_analisis}/captura")
def obtener_captura(id_analisis: str) -> Response:
    if not _ID_VALIDO.match(id_analisis):
        raise HTTPException(status_code=404)
    with _lock_capturas:
        datos = _capturas.get(id_analisis)
    if datos is None:
        raise HTTPException(status_code=404)
    # Content-Type fijo + nosniff: el navegador nunca la interpretará como HTML/JS.
    return Response(
        content=datos,
        media_type="image/jpeg",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )
