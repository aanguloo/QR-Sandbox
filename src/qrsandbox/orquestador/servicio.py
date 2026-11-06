"""Servicio interno del orquestador.

Interfaz ESTRECHA (como el monitor de OpenSSH): solo `POST /analizar {url}`.
Corre en una red Docker interna sin puertos publicados; solo la API lo alcanza.

La respuesta es un flujo NDJSON (una línea JSON por evento) para el análisis en vivo:
- eventos ya validados por el esquema cerrado (`navegacion`, `redireccion`, ...);
- `{"tipo": "captura", "t_ms", "jpeg_b64"}` con frames YA re-codificados;
- al final, `{"tipo": "resultado", "datos": <ResultadoAnalisis>}`.
"""

import base64
import json
import queue
import threading
from collections.abc import Iterator
from contextlib import asynccontextmanager

import docker
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from qrsandbox.comun.esquemas import SolicitudAnalisis
from qrsandbox.orquestador.ejecutor import ejecutar, limpiar_huerfanos

FIN = object()


@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    limpiar_huerfanos(docker.from_env())
    yield


app = FastAPI(title="QR-Sandbox orquestador", docs_url=None, redoc_url=None, lifespan=ciclo_de_vida)


@app.get("/health")
def health() -> dict[str, str]:
    return {"estado": "ok"}


def _linea(obj: dict) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def flujo_analisis(url: str, ejecutor=ejecutar) -> Iterator[bytes]:
    """Corre el análisis en un hilo y va entregando sus eventos como líneas NDJSON."""
    cola: queue.Queue = queue.Queue()

    def al_evento(evento: dict) -> None:
        if evento.get("tipo") == "captura":
            evento = {"tipo": "captura", "t_ms": evento["t_ms"],
                      "jpeg_b64": base64.b64encode(evento["jpeg"]).decode("ascii")}
        cola.put(_linea(evento))

    def correr() -> None:
        try:
            resultado = ejecutor(url, al_evento=al_evento)
            cola.put(_linea({"tipo": "resultado", "datos": resultado.model_dump(mode="json")}))
        finally:
            cola.put(FIN)

    threading.Thread(target=correr, daemon=True).start()
    while (linea := cola.get()) is not FIN:
        yield linea


@app.post("/analizar")
def analizar(solicitud: SolicitudAnalisis) -> StreamingResponse:
    # El semáforo del ejecutor limita cuántos workers viven a la vez.
    return StreamingResponse(flujo_analisis(solicitud.url), media_type="application/x-ndjson")
