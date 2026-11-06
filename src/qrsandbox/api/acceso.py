"""Código de acceso para la demo pública (Fase 8).

Mientras el túnel de Cloudflare está abierto, cualquiera con la URL podría usar el
servicio. Sin control, serviría como PROXY ABIERTO: alguien podría hacer que nuestro
sandbox visite sitios de terceros (escaneos, abuso) desde nuestra IP. Por eso, con
`DEMO_ACCESS_CODE` definido ("modo demo"):

- lanzar análisis y escribir en el log exige una cookie de acceso;
- la cookie se obtiene UNA vez ingresando el código; es `HttpOnly` (el JS no la lee: un
  XSS no la roba), `Secure` (solo viaja por HTTPS) y `SameSite=Strict` (otro sitio no
  puede usarla), y está firmada con HMAC y vence a las 12 h;
- el secreto de firma se genera al arrancar: reiniciar la API invalida todas las cookies;
- los intentos de código están limitados por IP (contra fuerza bruta) y se comparan en
  tiempo constante;
- detrás del túnel todos llegan desde la misma IP (la de cloudflared), así que la IP del
  cliente se toma de `CF-Connecting-IP`, que el borde de Cloudflare sobrescribe (el cliente
  no puede falsificarla). Solo en modo demo: fuera del túnel esa cabecera se ignora.

Las lecturas (ver un resultado, explorar el log) siguen abiertas: el log es público.
"""

import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from qrsandbox.api.seguridad import LimiteTasa

COOKIE = "qrs_acceso"
DURACION_S = 12 * 3600
VERSION = "acceso-v1"
_SECRETO = secrets.token_bytes(32)

limite_intentos = LimiteTasa(por_minuto=1, rafaga=5)  # 5 intentos y luego 1 por minuto

router = APIRouter(prefix="/acceso")


def codigo_demo() -> str:
    return os.environ.get("DEMO_ACCESS_CODE", "")


def modo_demo() -> bool:
    return bool(codigo_demo())


def emitir_token(ahora: float | None = None) -> str:
    ts = int(time.time() if ahora is None else ahora)
    firma = hmac.new(_SECRETO, f"{VERSION}|{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{firma}"


def token_valido(token: str | None, ahora: float | None = None) -> bool:
    if not token or token.count(".") != 1:
        return False
    ts_texto, firma = token.split(".")
    if not ts_texto.isdigit():
        return False
    esperada = hmac.new(_SECRETO, f"{VERSION}|{ts_texto}".encode(), hashlib.sha256).hexdigest()
    ahora = time.time() if ahora is None else ahora
    return hmac.compare_digest(firma, esperada) and 0 <= ahora - int(ts_texto) <= DURACION_S


def codigo_correcto(intento: str) -> bool:
    # Se comparan los hashes: tiempo constante aunque los largos difieran.
    a = hashlib.sha256(intento.encode()).digest()
    b = hashlib.sha256(codigo_demo().encode()).digest()
    return hmac.compare_digest(a, b)


def ip_cliente(request: Request) -> str:
    if modo_demo():
        cf = request.headers.get("cf-connecting-ip", "")
        try:
            return str(ipaddress.ip_address(cf.strip()))
        except ValueError:
            pass
    return request.client.host if request.client else "desconocido"


def tiene_acceso(request: Request) -> bool:
    return not modo_demo() or token_valido(request.cookies.get(COOKIE))


def exigir_acceso(request: Request) -> None:
    """Dependencia para lo que cuesta recursos o escribe: análisis y registros en el log."""
    if not tiene_acceso(request):
        raise HTTPException(401, "falta el código de acceso de la demo")


class PedidoAcceso(BaseModel):
    model_config = ConfigDict(extra="forbid")
    codigo: Annotated[str, Field(min_length=1, max_length=200)]


@router.get("/estado")
def estado(request: Request) -> dict:
    return {"requerido": modo_demo(), "ok": tiene_acceso(request)}


@router.post("")
def ingresar(pedido: PedidoAcceso, request: Request, response: Response) -> dict:
    if not modo_demo():
        return {"ok": True}
    if not limite_intentos.permitir(ip_cliente(request)):
        raise HTTPException(429, "demasiados intentos: espera un minuto")
    if not codigo_correcto(pedido.codigo):
        raise HTTPException(401, "código incorrecto")
    response.set_cookie(
        COOKIE, emitir_token(), max_age=DURACION_S, path="/",
        httponly=True, secure=True, samesite="strict",
    )
    return {"ok": True}


@router.post("/salir")
def salir(response: Response) -> dict:
    response.delete_cookie(COOKIE, path="/", httponly=True, secure=True, samesite="strict")
    return {"ok": True}
