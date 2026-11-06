"""Endpoints del QR Transparency Log.

Todo lo que el servidor entrega (STH, pruebas, hojas) es verificable por el cliente
sin confiar en el servidor: el navegador (Fase 5) y el auditor (`scripts/auditor.py`)
recalculan hashes y verifican firmas por su cuenta.

Privacidad en /log/consultar: la ubicación se redondea a ~110 m dentro del log y no se
guarda ni se registra en ningún lado (el cuerpo de la petición no aparece en los logs).
"""

import os
from pathlib import Path
from threading import Lock
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from qrsandbox.comun.esquemas import Url
from qrsandbox.tlog.log import LogTransparencia, RegistroRechazado, cargar_o_crear_clave
from qrsandbox.tlog.registro import ClavePublica, SolicitudRegistro

router = APIRouter(prefix="/log")

_log: LogTransparencia | None = None
_lock = Lock()
MAX_PAGINA = 500


def obtener_log() -> LogTransparencia:
    global _log
    with _lock:
        if _log is None:
            ruta_db = Path(os.environ.get("TLOG_DB", "data/tlog.sqlite"))
            ruta_db.parent.mkdir(parents=True, exist_ok=True)
            clave = cargar_o_crear_clave(Path(os.environ.get("TLOG_CLAVE", "data/tlog_clave.pem")))
            _log = LogTransparencia(ruta_db, clave)
        return _log


Log = Annotated[LogTransparencia, Depends(obtener_log)]


class Consulta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: Url
    lat: Annotated[float, Field(ge=-90, le=90)]
    lon: Annotated[float, Field(ge=-180, le=180)]


def _hex(ruta: list[bytes]) -> list[str]:
    return [h.hex() for h in ruta]


@router.get("/clave-publica")
def clave_publica(log: Log) -> dict:
    return {"algoritmo": "Ed25519", "clave_publica": log.clave_publica}


@router.get("/sth")
def sth_actual(log: Log) -> dict:
    return log.sth().a_dict()


@router.get("/sth/{tamano}")
def sth_historico(tamano: int, log: Log) -> dict:
    sth = log.sth(tamano)
    if sth is None:
        raise HTTPException(404, "no hay STH para ese tamaño")
    return sth.a_dict()


@router.post("/registros", status_code=201)
def registrar(solicitud: SolicitudRegistro, log: Log) -> dict:
    try:
        return log.agregar(solicitud)
    except RegistroRechazado as e:
        raise HTTPException(400, str(e)) from None


@router.get("/registros")
def listar(
    log: Log,
    desde: Annotated[int, Query(ge=0)] = 0,
    limite: Annotated[int, Query(ge=1, le=MAX_PAGINA)] = 100,
) -> dict:
    return {"entradas": log.entradas(desde, limite), "tamano": log.tamano()}


@router.get("/registros/{indice}")
def entrada(indice: int, log: Log) -> dict:
    e = log.entrada(indice)
    if e is None:
        raise HTTPException(404, "no existe esa entrada")
    return e


@router.get("/prueba-inclusion")
def prueba_inclusion(
    log: Log, indice: Annotated[int, Query(ge=0)], tamano: Annotated[int, Query(ge=1)]
) -> dict:
    try:
        ruta = log.prueba_inclusion(indice, tamano)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"indice": indice, "tamano": tamano, "ruta": _hex(ruta)}


@router.get("/prueba-consistencia")
def prueba_consistencia(
    log: Log, primero: Annotated[int, Query(ge=1)], segundo: Annotated[int, Query(ge=1)]
) -> dict:
    try:
        ruta = log.prueba_consistencia(primero, segundo)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"primero": primero, "segundo": segundo, "ruta": _hex(ruta)}


@router.post("/consultar")
def consultar(consulta: Consulta, log: Log) -> dict:
    return log.consultar(consulta.url, consulta.lat, consulta.lon)


@router.get("/por-clave")
def por_clave(log: Log, clave: Annotated[ClavePublica, Query()]) -> dict:
    """Vista de auditoría: todo lo registrado con una clave pública."""
    return {"clave_publica": clave, "entradas": log.por_clave(clave)}
