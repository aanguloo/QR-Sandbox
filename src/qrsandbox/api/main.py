"""Aplicación FastAPI de QR-Sandbox (API pública + web).

La API NO tiene acceso a Docker: para analizar una URL le pide al orquestador,
por una red interna, que lo haga (interfaz estrecha: solo "analizar URL").

Páginas: `/` (escanear), `/analisis/{id}` (resultado en vivo), `/comercio`, `/log`.
Datos: `POST /analisis`, `GET /analisis/{id}/eventos` (SSE), `/analisis/{id}/resultado`,
`/analisis/{id}/captura`, y el QR Transparency Log en `/log/...`.
"""

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator

from qrsandbox import __version__
from qrsandbox.api import analisis as A
from qrsandbox.api.acceso import exigir_acceso
from qrsandbox.api.acceso import router as router_acceso
from qrsandbox.api.log import obtener_log
from qrsandbox.api.log import router as router_log
from qrsandbox.api.seguridad import MiddlewareSeguridad, exigir_cupo_analisis
from qrsandbox.comun.esquemas import Url
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.senales.red import ProveedorRed, ProveedorRedReal
from qrsandbox.tlog.log import LogTransparencia

WEB = Path(os.environ.get("WEB_DIR", Path(__file__).resolve().parents[3] / "web"))
MAX_SSE = 100  # conexiones SSE simultáneas (anti-DoS)
INTERVALO_SSE_S = 0.25
LATIDO_SSE_S = 10
RELLENO_SSE = int(os.environ.get("RELLENO_SSE", "2048"))  # bytes; ver comentario en eventos()

# docs_url/redoc_url desactivados: no exponemos la UI de Swagger (scripts de
# terceros desde CDN) en un servicio que se publicará por un túnel en la demo.
app = FastAPI(title="QR-Sandbox", version=__version__, docs_url=None, redoc_url=None)
app.add_middleware(MiddlewareSeguridad)
app.include_router(router_log)  # QR Transparency Log (Fase 3)
app.include_router(router_acceso)  # código de acceso de la demo pública (Fase 8)
if (WEB / "static").is_dir():
    app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")


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
_sse_abiertas = 0


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


def _analisis(id_analisis: str) -> A.Analisis:
    a = A.almacen.obtener(id_analisis)
    if a is None:
        raise HTTPException(404, "no existe ese análisis")
    return a


# ------------------------------------------------------------------ API


@app.get("/health")
def health() -> dict[str, str]:
    """Chequeo de vida usado por el healthcheck de docker compose."""
    return {"estado": "ok", "version": __version__}


# Orden: primero el código de acceso (sin él no se gasta cupo), luego el límite de tasa.
@app.post("/analisis", status_code=202,
          dependencies=[Depends(exigir_acceso), Depends(exigir_cupo_analisis)])
def crear_analisis(
    peticion: PeticionAnalisis,
    log: Annotated[LogTransparencia, Depends(obtener_log)],
    response: Response,
    esperar: Annotated[bool, Query()] = False,
) -> dict:
    """Lanza un análisis. Por defecto responde al tiro con el id (el progreso va por SSE).
    Con `?esperar=true` responde al terminar (útil para scripts y experimentos)."""
    try:
        a = A.almacen.crear(peticion.url, peticion.lat, peticion.lon)
    except A.AlmacenLleno:
        raise HTTPException(503, "demasiados análisis en curso") from None
    if esperar:
        A.ejecutar_analisis(a, log, listas_negras(), proveedor_red())
        if a.estado == "error":
            mensaje = a.desde(0)[-1].datos["mensaje"]
            raise HTTPException(503, mensaje)
        response.status_code = 200
        return a.resultado
    A.hilos.submit(A.ejecutar_analisis, a, log, listas_negras(), proveedor_red())
    return {
        "id": a.id,
        "pagina": f"/analisis/{a.id}",
        "eventos": f"/analisis/{a.id}/eventos",
        "resultado": f"/analisis/{a.id}/resultado",
    }


@app.get("/analisis/{id_analisis}/resultado")
def resultado(id_analisis: str) -> dict:
    a = _analisis(id_analisis)
    return {"id": a.id, "url": a.url, "estado": a.estado, "resultado": a.resultado}


@app.get("/analisis/{id_analisis}/eventos")
async def eventos(id_analisis: str, request: Request) -> StreamingResponse:
    """Server-Sent Events: línea de tiempo + frames del sandbox + veredicto final.

    Al conectarse se reenvía todo lo ocurrido hasta ahora (sirve al recargar la página).
    Los frames van como JPEG en base64; el navegador los muestra desde un `blob:` con
    tipo `image/jpeg` fijo. Solo se envía el frame más reciente (un cliente lento se
    salta frames en vez de acumularlos).
    """
    a = _analisis(id_analisis)
    if _sse_abiertas >= MAX_SSE:
        raise HTTPException(503, "demasiadas conexiones en vivo")

    async def generar():
        global _sse_abiertas
        _sse_abiertas += 1
        try:
            # Relleno inicial (comentario SSE, el navegador lo ignora): fuerza a los
            # intermediarios (p. ej. el borde de Cloudflare en la demo) a vaciar su búfer.
            yield ":" + " " * RELLENO_SSE + "\n\n"
            seq, frame_visto, ultimo_envio = 0, 0, time.monotonic()
            while True:
                if await request.is_disconnected():
                    return
                if time.monotonic() - ultimo_envio > LATIDO_SSE_S:
                    ultimo_envio = time.monotonic()
                    yield ": latido\n\n"
                if a.frame_seq != frame_visto and a.frame is not None:
                    frame_visto = a.frame_seq
                    datos = {"jpeg_b64": base64.b64encode(a.frame).decode("ascii")}
                    ultimo_envio = time.monotonic()
                    yield f"event: frame\ndata: {json.dumps(datos)}\n\n"
                nuevos = a.desde(seq)
                for e in nuevos:
                    ultimo_envio = time.monotonic()
                    seq = e.seq + 1
                    yield f"id: {e.seq}\nevent: {e.tipo}\ndata: {json.dumps(e.datos)}\n\n"
                if a.terminado and not nuevos:
                    return
                await asyncio.sleep(INTERVALO_SSE_S)
        finally:
            _sse_abiertas -= 1

    return StreamingResponse(
        generar(),
        # Tipo EXACTO "text/event-stream" (sin "; charset=utf-8", que Starlette agrega si se
        # usa media_type): cloudflared solo vacía su búfer al instante si es exactamente ese.
        # Con el charset, a través del túnel la línea de tiempo llegaba toda junta al final.
        # no-transform: que ningún intermediario comprima (comprimir también junta en búfer).
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-store, no-transform",
                 "X-Accel-Buffering": "no"},
    )


@app.get("/analisis/{id_analisis}/progreso")
def progreso(id_analisis: str, desde: Annotated[int, Query(ge=0)] = 0) -> dict:
    """Mismo contenido que el SSE, por sondeo (respaldo del navegador cuando un intermediario
    retiene el SSE). Los frames no van aquí: se piden aparte en /frame (image/jpeg)."""
    a = _analisis(id_analisis)
    nuevos = a.desde(desde)[:200]
    return {
        "estado": a.estado,
        "frame_seq": a.frame_seq,
        "eventos": [{"seq": e.seq, "tipo": e.tipo, "datos": e.datos} for e in nuevos],
    }


@app.get("/analisis/{id_analisis}/frame")
def frame_actual(id_analisis: str) -> Response:
    a = _analisis(id_analisis)
    if a.frame is None:
        raise HTTPException(404, "todavía no hay imagen")
    return Response(content=a.frame, media_type="image/jpeg",
                    headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@app.get("/analisis/{id_analisis}/captura")
def obtener_captura(id_analisis: str) -> Response:
    a = _analisis(id_analisis)
    datos = a.captura or a.frame
    if datos is None:
        raise HTTPException(404, "todavía no hay captura")
    # Ruta separada + Content-Type fijo + nosniff: el navegador nunca la interpretará
    # como HTML/JS, aunque el atacante controle lo que se ve en la imagen.
    return Response(
        content=datos,
        media_type="image/jpeg",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )


@app.get("/analisis/{id_analisis}/fotos/{n}")
def obtener_foto(id_analisis: str, n: int) -> Response:
    """Fotos paso a paso: mismas garantías que la captura (JPEG re-codificado, tipo fijo)."""
    a = _analisis(id_analisis)
    if not 0 <= n < len(a.fotos):
        raise HTTPException(404, "no existe esa foto")
    return Response(
        content=a.fotos[n][2],
        media_type="image/jpeg",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, max-age=3600"},
    )


# ------------------------------------------------------------------ páginas


def _pagina(nombre: str) -> FileResponse:
    return FileResponse(WEB / nombre, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-cache"})


@app.get("/", include_in_schema=False)
def pagina_escanear() -> FileResponse:
    return _pagina("index.html")


@app.get("/analisis/{id_analisis}", include_in_schema=False)
def pagina_analisis(id_analisis: str) -> FileResponse:
    if not A.ID_VALIDO.match(id_analisis):
        raise HTTPException(404)
    return _pagina("analisis.html")


@app.get("/comercio", include_in_schema=False)
def pagina_comercio() -> FileResponse:
    return _pagina("comercio.html")


@app.get("/log", include_in_schema=False)
def pagina_log() -> FileResponse:
    return _pagina("log.html")


@app.get("/ayuda", include_in_schema=False)
def pagina_ayuda() -> FileResponse:
    return _pagina("ayuda.html")


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifiesto() -> FileResponse:
    return FileResponse(WEB / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
def service_worker() -> FileResponse:
    # En la raíz para que su alcance cubra todo el sitio.
    return FileResponse(WEB / "sw.js", media_type="text/javascript",
                        headers={"Cache-Control": "no-cache"})
