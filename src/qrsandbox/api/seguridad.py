"""Seguridad web de la API (clases de Seguridad Web y Top Web Attacks).

Middleware ASGI puro (no BaseHTTPMiddleware) para no interferir con el streaming SSE.

1. Cabeceras en TODAS las respuestas:
   - CSP estricta: solo scripts/estilos del propio origen, sin inline ni eval; imágenes
     propias, `blob:` (frames del sandbox) y teselas de OpenStreetMap; `frame-ancestors
     'none'` + `X-Frame-Options: DENY` contra clickjacking; `object-src`/`base-uri` cerrados.
   - `nosniff`, `Referrer-Policy`, `Permissions-Policy` (cámara y ubicación solo aquí),
     aislamiento entre orígenes (COOP/CORP).
2. Anti-CSRF en métodos que modifican estado (POST/PUT/PATCH/DELETE):
   - cabecera propia `X-QRSandbox-CSRF: 1`: un formulario o <img> de otro sitio no puede
     ponerla, y fetch() cross-origin con ella dispara un preflight CORS que no autorizamos;
   - `Content-Type: application/json` obligatorio (bloquea el truco del form text/plain);
   - si viene `Origin`, debe ser este mismo host.
   Hoy la API no usa cookies (las firmas del comercio son la autenticación), pero el
   código de acceso de la demo (Fase 8) sí usará una cookie: la defensa ya está puesta.
3. Límite de análisis por cliente (cada análisis levanta un navegador: es caro).
"""

import json
import os
import time
from collections import OrderedDict
from threading import Lock
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

CSP = "; ".join([  # noqa: FLY002 - una directiva por línea se lee mejor
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' blob: data: https://tile.openstreetmap.org",
    "connect-src 'self'",
    "manifest-src 'self'",
    "worker-src 'self'",
    "font-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
])
CABECERAS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    # Solo el origen (no la ruta) a terceros: OSM pide Referer para sus teselas, y así no
    # se filtra el id del análisis. Los enlaces al destino usan rel="noreferrer".
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(self), geolocation=(self), microphone=(), payment=(), usb=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
METODOS_INSEGUROS = {"POST", "PUT", "PATCH", "DELETE"}
CABECERA_CSRF = b"x-qrsandbox-csrf"


def motivo_csrf(metodo: str, cabeceras: dict[bytes, bytes]) -> str | None:
    """None si la petición pasa la defensa anti-CSRF; si no, el motivo."""
    if metodo not in METODOS_INSEGUROS:
        return None
    if cabeceras.get(CABECERA_CSRF) != b"1":
        return "falta la cabecera anti-CSRF"
    tipo = cabeceras.get(b"content-type", b"").split(b";")[0].strip().lower()
    if tipo != b"application/json":
        return "Content-Type debe ser application/json"
    origen = cabeceras.get(b"origin")
    if origen is not None:
        host = cabeceras.get(b"host", b"").decode("latin-1")
        if urlsplit(origen.decode("latin-1")).netloc != host:
            return "origen cruzado no permitido"
    return None


class MiddlewareSeguridad:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        cabeceras = dict(scope["headers"])
        motivo = motivo_csrf(scope["method"], cabeceras)

        # Detrás del túnel la conexión del navegador es HTTPS (cloudflared nos habla en http
        # interno y avisa con X-Forwarded-Proto): ahí se agrega HSTS.
        https = cabeceras.get(b"x-forwarded-proto") == b"https"

        async def enviar(mensaje):
            if mensaje["type"] == "http.response.start":
                existentes = {k.lower() for k, _ in mensaje.get("headers", [])}
                mensaje["headers"] = list(mensaje.get("headers", [])) + [
                    (k, v) for k, v in CABECERAS if k not in existentes
                ]
                if https:
                    mensaje["headers"].append((b"strict-transport-security", b"max-age=86400"))
            await send(mensaje)

        if motivo:
            cuerpo = json.dumps({"detail": motivo}).encode()
            await enviar({"type": "http.response.start", "status": 403,
                          "headers": [(b"content-type", b"application/json")]})
            await enviar({"type": "http.response.body", "body": cuerpo})
            return
        await self.app(scope, receive, enviar)


class LimiteTasa:
    """Token bucket por cliente (en memoria)."""

    def __init__(self, por_minuto: float, rafaga: int, max_clientes: int = 10_000):
        self.por_s = por_minuto / 60
        self.rafaga = rafaga
        self.max_clientes = max_clientes
        self._clientes: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = Lock()

    def permitir(self, cliente: str, ahora: float | None = None) -> bool:
        ahora = time.monotonic() if ahora is None else ahora
        with self._lock:
            fichas, antes = self._clientes.pop(cliente, (self.rafaga, ahora))
            fichas = min(self.rafaga, fichas + (ahora - antes) * self.por_s)
            permitido = fichas >= 1
            self._clientes[cliente] = (fichas - 1 if permitido else fichas, ahora)
            while len(self._clientes) > self.max_clientes:
                self._clientes.popitem(last=False)
            return permitido


limite_analisis = LimiteTasa(
    por_minuto=float(os.environ.get("LIMITE_ANALISIS_POR_MIN", "10")),
    rafaga=int(os.environ.get("LIMITE_ANALISIS_RAFAGA", "5")),
)
# Límite para TODOS los clientes juntos (en la demo pública: 20/min). 0 = desactivado.
_global_por_min = float(os.environ.get("LIMITE_GLOBAL_POR_MIN", "0"))
limite_global = LimiteTasa(por_minuto=_global_por_min, rafaga=max(1, int(_global_por_min / 2))) \
    if _global_por_min else None


def exigir_cupo_analisis(request: Request) -> None:
    from qrsandbox.api.acceso import ip_cliente  # import tardío: acceso usa LimiteTasa

    if not limite_analisis.permitir(ip_cliente(request)):
        raise HTTPException(429, "demasiados análisis: espera un momento")
    if limite_global is not None and not limite_global.permitir("global"):
        raise HTTPException(429, "el servicio está ocupado: intenta en un minuto")
