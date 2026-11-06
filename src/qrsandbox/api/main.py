"""Aplicación FastAPI de QR-Sandbox (API pública).

La API NO tiene acceso a Docker: para analizar una URL le pide al orquestador,
por una red interna, que lo haga (interfaz estrecha: solo "analizar URL").
"""

import base64
import os
import re
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from qrsandbox import __version__
from qrsandbox.api.log import obtener_log
from qrsandbox.api.log import router as router_log
from qrsandbox.comun.esquemas import ResultadoAnalisis, Url
from qrsandbox.senales.dominio import partes_host
from qrsandbox.senales.estaticas import analizar_url
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.senales.red import ProveedorRed, ProveedorRedReal
from qrsandbox.tlog.log import LogTransparencia
from qrsandbox.veredicto.motor import evaluar

ORQUESTADOR_URL = os.environ.get("ORQUESTADOR_URL", "http://127.0.0.1:9000")
TIMEOUT_ORQUESTADOR_S = 45.0
MAX_CAPTURAS_EN_MEMORIA = 50
_ID_VALIDO = re.compile(r"^[0-9a-f]{12}$")

# docs_url/redoc_url desactivados: no exponemos la UI de Swagger (scripts de
# terceros desde CDN) en un servicio que se publicará por un túnel en la demo.
app = FastAPI(title="QR-Sandbox", version=__version__, docs_url=None, redoc_url=None)
app.include_router(router_log)  # QR Transparency Log (Fase 3)

# Fase 1: capturas en memoria (LRU acotado). La persistencia llega con SQLite.
_capturas: OrderedDict[str, bytes] = OrderedDict()
_lock_capturas = Lock()


def _guardar_captura(id_analisis: str, datos: bytes) -> None:
    with _lock_capturas:
        _capturas[id_analisis] = datos
        while len(_capturas) > MAX_CAPTURAS_EN_MEMORIA:
            _capturas.popitem(last=False)


class PeticionAnalisis(BaseModel):
    """Lo que manda la web: el texto del QR y, opcionalmente, la ubicación aproximada."""

    model_config = ConfigDict(extra="forbid")
    url: Url
    lat: Annotated[float | None, Field(ge=-90, le=90)] = None
    lon: Annotated[float | None, Field(ge=-180, le=180)] = None

    @model_validator(mode="after")
    def _ambas_o_ninguna(self):
        if (self.lat is None) != (self.lon is None):
            raise ValueError("lat y lon van juntas")
        return self


_listas: ListasNegras | None = None
_red: ProveedorRed | None = None


def listas_negras() -> ListasNegras:
    global _listas
    if _listas is None:
        _listas = ListasNegras.desde_directorio()
    return _listas


def proveedor_red() -> ProveedorRed | None:
    """RDAP + TLS solo si SENALES_RED=1 (en compose). En tests y sin red: desactivado."""
    global _red
    if os.environ.get("SENALES_RED") != "1":
        return None
    if _red is None:
        _red = ProveedorRedReal()
    return _red


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
def crear_analisis(
    peticion: PeticionAnalisis, log: Annotated[LogTransparencia, Depends(obtener_log)]
) -> dict:
    url = peticion.url
    # Señales estáticas (incluye RDAP/TLS, que tardan) EN PARALELO con el sandbox.
    with ThreadPoolExecutor(max_workers=2) as ejecutor:
        futuro_sandbox = ejecutor.submit(pedir_analisis, url)
        futuro_estatico = ejecutor.submit(
            analizar_url, url, listas=listas_negras(), red=proveedor_red()
        )
        try:
            crudo = futuro_sandbox.result()
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="orquestador no disponible") from None
        estatico = futuro_estatico.result()
    try:
        # El orquestador es de confianza, pero re-validamos su respuesta de todas formas:
        # es barato y evita que un bug allá se convierta en un bug acá.
        r = ResultadoAnalisis.model_validate(crudo)
    except ValidationError:
        raise HTTPException(status_code=502, detail="respuesta inválida del orquestador") from None

    # Si la página terminó en otro host, también se analiza estáticamente el destino final.
    estatico_final = None
    final = r.resultado.url_final if r.resultado else None
    if final and partes_host(final).host != estatico.partes.host:
        estatico_final = analizar_url(final, listas=listas_negras(), red=proveedor_red())

    consulta_log = None
    if peticion.lat is not None:
        consulta_log = log.consultar(url, peticion.lat, peticion.lon)

    salida = r.model_dump(mode="json", exclude={"captura_jpeg_b64"})
    salida["captura_url"] = None
    if r.captura_jpeg_b64:
        _guardar_captura(r.id, base64.b64decode(r.captura_jpeg_b64))
        salida["captura_url"] = f"/analisis/{r.id}/captura"
    salida["veredicto"] = evaluar(estatico, estatico_final, r, consulta_log, listas=listas_negras())
    salida["senales_estaticas"] = {
        "inicial": estatico.datos,
        "final": estatico_final.datos if estatico_final else None,
    }
    salida["log"] = consulta_log
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
