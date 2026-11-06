"""Servicio interno del orquestador.

Interfaz ESTRECHA (como el monitor de OpenSSH): solo `POST /analizar {url}`.
Corre en una red Docker interna sin puertos publicados; solo la API lo alcanza.
"""

from contextlib import asynccontextmanager

import docker
from fastapi import FastAPI

from qrsandbox.comun.esquemas import ResultadoAnalisis, SolicitudAnalisis
from qrsandbox.orquestador.ejecutor import ejecutar, limpiar_huerfanos


@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    limpiar_huerfanos(docker.from_env())
    yield


app = FastAPI(title="QR-Sandbox orquestador", docs_url=None, redoc_url=None, lifespan=ciclo_de_vida)


@app.get("/health")
def health() -> dict[str, str]:
    return {"estado": "ok"}


@app.post("/analizar")
def analizar(solicitud: SolicitudAnalisis) -> ResultadoAnalisis:
    # Endpoint síncrono: FastAPI lo corre en un hilo; el semáforo del ejecutor
    # limita cuántos workers viven a la vez.
    return ejecutar(solicitud.url)
