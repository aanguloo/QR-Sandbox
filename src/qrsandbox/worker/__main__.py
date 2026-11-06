"""Worker desechable: visita UNA URL con Chromium y reporta lo que observa.

Se ejecuta dentro de un contenedor efímero lanzado por el orquestador:
    python -m qrsandbox.worker <url>

Diseño de seguridad:
- No depende del resto del paquete (la imagen solo contiene este módulo y Playwright):
  menos código dentro del dominio sacrificable.
- No tiene conexión con la API ni con el navegador del usuario: su ÚNICA salida es
  stdout, un evento JSON por línea, que el orquestador valida como dato tainted.
- Regla ética: SOLO carga la página. Nunca hace clic, escribe ni envía formularios.
  Descargas, popups y diálogos se bloquean/cierran.
"""

import asyncio
import base64
import ipaddress
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

from playwright.async_api import Error as ErrorPlaywright
from playwright.async_api import TimeoutError as TimeoutPlaywright
from playwright.async_api import async_playwright

TIMEOUT_TOTAL_S = 17  # el orquestador mata el contenedor a los 20 s de todas formas
TIMEOUT_NAVEGACION_MS = 12_000
ESPERA_POST_CARGA_MS = 1_500  # deja correr redirecciones por JS / meta refresh tardías
MAX_TERCEROS_EMITIDOS = 50
MAX_CAPTURA_BYTES = 200_000
SCREENCAST_INTERVALO_S = 0.4  # ~2,5 fps
VIEWPORT = {"width": 390, "height": 844}  # resolución de celular
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
)

_T0 = time.monotonic()


def emitir(tipo: str, **datos) -> None:
    """Escribe un evento como una línea JSON en stdout."""
    evento = {"tipo": tipo, "t_ms": int((time.monotonic() - _T0) * 1000), **datos}
    sys.stdout.write(json.dumps(evento, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def es_http(url: str | None) -> bool:
    return bool(url) and urlsplit(url).scheme in ("http", "https")


def host_de(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def dominio_base(host: str) -> str:
    """Aproximación al dominio registrable (últimas 2 etiquetas).

    Simplificación consciente: no usa la Public Suffix List (p. ej. trata `gob.cl`
    como base). Basta para contar terceros; las señales finas van en la Fase 4.
    """
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    etiquetas = host.split(".")
    return ".".join(etiquetas[-2:]) if len(etiquetas) >= 2 else host


PROXY = os.environ.get("QRS_PROXY", "")


async def iniciar_screencast(contexto, pagina) -> None:
    """Vista previa en vivo vía CDP (Page.startScreencast), limitada a ~2,5 fps.

    Solo salen imágenes JPEG (nunca HTML/JS): el orquestador además las re-codifica.
    """
    cdp = await contexto.new_cdp_session(pagina)
    ultimo = [0.0]

    async def al_frame(params) -> None:
        try:
            await cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
        except ErrorPlaywright:
            return
        ahora = time.monotonic()
        datos = params.get("data", "")
        if ahora - ultimo[0] >= SCREENCAST_INTERVALO_S and len(datos) * 3 // 4 <= MAX_CAPTURA_BYTES:
            ultimo[0] = ahora
            emitir("captura", jpeg_b64=datos)

    cdp.on("Page.screencastFrame", lambda params: asyncio.ensure_future(al_frame(params)))
    await cdp.send(
        "Page.startScreencast",
        {"format": "jpeg", "quality": 50, "maxWidth": VIEWPORT["width"], "maxHeight": VIEWPORT["height"]},
    )


async def analizar(url: str) -> None:
    redirecciones: list[str] = []
    navegaciones: list[str] = []
    dominios_vistos: set[str] = set()
    base_inicial = dominio_base(host_de(url))

    async with async_playwright() as p:
        # Chromium corre con --no-sandbox (default de Playwright): su sandbox interno
        # necesita user namespaces/SUID, que el contenedor endurecido no ofrece.
        # El aislamiento lo dan el contenedor y el runtime (runc endurecido / gVisor).
        navegador = await p.chromium.launch(
            # Toda conexión sale por el proxy anti-SSRF. "<-loopback>" QUITA la excepción
            # implícita de Chromium para localhost/127.0.0.1: también esas van al proxy
            # (y el proxy las bloquea). Igual la red del contenedor no tiene otra salida.
            proxy={"server": PROXY, "bypass": "<-loopback>"},
            args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                # WebRTC podría mandar UDP directo, sin pasar por el proxy.
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-background-networking",  # nada de tráfico propio de Chromium
                "--dns-prefetch-disable",
                "--no-pings",  # sin <a ping> (rastreo)
            ],
        )
        contexto = await navegador.new_context(
            viewport=VIEWPORT,
            user_agent=USER_AGENT,
            is_mobile=True,
            has_touch=True,
            locale="es-CL",
            accept_downloads=False,  # nunca guardar archivos de la página
            service_workers="block",  # que la página no deje código persistente
        )
        pagina = await contexto.new_page()
        await iniciar_screencast(contexto, pagina)

        def al_request(req) -> None:
            try:
                if req.redirected_from and req.is_navigation_request() and req.frame == pagina.main_frame:
                    desde = req.redirected_from.url
                    if es_http(desde) and es_http(req.url):
                        redirecciones.append(req.url)
                        emitir("redireccion", desde=desde, hacia=req.url)
                host = host_de(req.url)
                if not host or not es_http(req.url):
                    return
                base = dominio_base(host)
                actual = dominio_base(host_de(pagina.url)) if es_http(pagina.url) else base_inicial
                if base != actual and base not in dominios_vistos:
                    dominios_vistos.add(base)
                    if len(dominios_vistos) <= MAX_TERCEROS_EMITIDOS:
                        emitir("request_tercero", dominio=base)
            except ErrorPlaywright:
                pass

        def al_responder(resp) -> None:
            # El proxy marca sus bloqueos con una cabecera; lo informamos en la línea de tiempo.
            try:
                motivo = resp.headers.get("x-qrsandbox-bloqueo")
                if motivo and resp.request.is_navigation_request():
                    motivo = re.sub(r"[^a-z0-9_]", "", motivo.lower())[:40]
                    emitir("error", mensaje=f"egreso bloqueado por el proxy ({motivo}): {resp.url[:300]}")
            except ErrorPlaywright:
                pass

        def al_navegar(frame) -> None:
            es_nueva = not navegaciones or navegaciones[-1] != frame.url
            if frame == pagina.main_frame and es_http(frame.url) and es_nueva:
                navegaciones.append(frame.url)
                emitir("navegacion", url=frame.url)

        def al_descargar(descarga) -> None:
            if es_http(descarga.url):
                emitir("descarga_bloqueada", url=descarga.url, nombre=descarga.suggested_filename[:255])
            asyncio.ensure_future(descarga.cancel())

        pagina.on("request", al_request)
        pagina.on("response", al_responder)
        pagina.on("framenavigated", al_navegar)
        pagina.on("download", al_descargar)
        pagina.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
        # Ventanas nuevas (popups, target=_blank) se cierran: solo analizamos una página.
        contexto.on("page", lambda pg: asyncio.ensure_future(pg.close()) if pg != pagina else None)

        estado_http = None
        tiempo_carga_ms = None
        t_inicio = time.monotonic()
        try:
            respuesta = await pagina.goto(url, wait_until="load", timeout=TIMEOUT_NAVEGACION_MS)
            estado_http = respuesta.status if respuesta else None
            tiempo_carga_ms = int((time.monotonic() - t_inicio) * 1000)
        except TimeoutPlaywright:
            emitir("error", mensaje="timeout de carga")
        except ErrorPlaywright as e:
            emitir("error", mensaje=str(e).splitlines()[0][:400])

        await pagina.wait_for_timeout(ESPERA_POST_CARGA_MS)

        titulo = ""
        formularios_password = 0
        try:
            titulo = (await pagina.title())[:300]
            for frame in pagina.frames:
                formularios_password += await frame.locator("input[type=password]").count()
        except ErrorPlaywright:
            pass
        if formularios_password:
            emitir("formulario_password", cantidad=min(formularios_password, 1000))

        try:
            jpeg = await pagina.screenshot(type="jpeg", quality=60, timeout=3_000)
            if len(jpeg) <= MAX_CAPTURA_BYTES:
                emitir("captura", jpeg_b64=base64.b64encode(jpeg).decode("ascii"))
        except ErrorPlaywright:
            pass

        url_final = pagina.url if es_http(pagina.url) else (navegaciones[-1] if navegaciones else None)
        base_final = dominio_base(host_de(url_final)) if url_final else base_inicial
        terceros = sorted(d for d in dominios_vistos if d != base_final)

        cadena = [url]
        for u in redirecciones + navegaciones:
            if u != cadena[-1]:
                cadena.append(u)

        emitir(
            "fin",
            resultado={
                "url_inicial": url,
                "url_final": url_final,
                "cadena_redirecciones": cadena[:30],
                "titulo": titulo,
                "estado_http": estado_http,
                "formularios_password": formularios_password,
                "dominios_terceros": terceros[:50],
                "n_dominios_terceros": len(terceros),
                "tiempo_carga_ms": tiempo_carga_ms,
            },
        )
        await navegador.close()


def main() -> int:
    if not PROXY:
        # Falla cerrado: sin proxy no se navega (nunca salir "directo" por error de config).
        emitir("error", mensaje="falta QRS_PROXY: el worker no navega sin el proxy de salida")
        emitir("fin", resultado=None)
        return 3
    if len(sys.argv) != 2 or not es_http(sys.argv[1]):
        emitir("error", mensaje="uso: python -m qrsandbox.worker <url http/https>")
        emitir("fin", resultado=None)
        return 2
    try:
        asyncio.run(asyncio.wait_for(analizar(sys.argv[1]), TIMEOUT_TOTAL_S))
    except TimeoutError:
        emitir("error", mensaje="timeout total del worker")
        emitir("fin", resultado=None)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
