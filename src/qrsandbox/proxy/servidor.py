"""Proxy de salida anti-SSRF (HTTP forward proxy + CONNECT), solo stdlib.

Es la ÚNICA salida a internet de los workers (están en una red Docker interna).
Por cada conexión del worker:
1. Lee la petición (CONNECT host:puerto para HTTPS, o "GET http://host/..." para HTTP).
2. Resuelve el host UNA vez y aplica `politica.motivo_bloqueo` a TODAS las IPs
   resueltas: si alguna es interna se bloquea todo (un registro DNS mixto público +
   privado es una técnica de rebinding).
3. Se conecta a la IP ya validada, nunca vuelve a resolver el nombre.
4. Como cada redirección del navegador abre una petición nueva al proxy, también se
   revalidan los saltos de una cadena de redirecciones.
Cada decisión se registra como una línea JSON en stdout (evidencia para el Exp. 2).

En HTTP plano se fuerza `Connection: close`: una conexión TCP del worker queda atada
a UN destino validado, así no puede "colar" una segunda petición a otro host.
"""

import asyncio
import json
import os
import socket
import sys
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from qrsandbox.proxy.politica import motivo_bloqueo

MAX_CABECERAS = 16_384  # bytes de la petición inicial (anti-DoS)
TIMEOUT_CABECERAS_S = 10
TIMEOUT_CONEXION_S = 5
TIMEOUT_INACTIVIDAD_S = 20
MAX_CONEXIONES = 256

Resolver = Callable[[str, int], Awaitable[list[str]]]
Politica = Callable[[str, int], str | None]


def registrar(**campos) -> None:
    campos["t"] = round(time.time(), 3)
    sys.stdout.write(json.dumps(campos, ensure_ascii=False) + "\n")
    sys.stdout.flush()


async def resolver_dns(host: str, puerto: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, puerto, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return list(dict.fromkeys(info[4][0] for info in infos))


class ProxyEgreso:
    def __init__(self, resolver: Resolver = resolver_dns, politica: Politica = motivo_bloqueo):
        self.resolver = resolver
        self.politica = politica
        self._cupos = asyncio.Semaphore(MAX_CONEXIONES)

    async def atender(self, lector: asyncio.StreamReader, escritor: asyncio.StreamWriter) -> None:
        async with self._cupos:
            try:
                await self._atender(lector, escritor)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                escritor.close()

    async def _atender(self, lector, escritor) -> None:
        try:
            cabecera = await asyncio.wait_for(
                lector.readuntil(b"\r\n\r\n"), TIMEOUT_CABECERAS_S
            )
        except asyncio.LimitOverrunError:
            await self._responder(escritor, 431, "cabeceras demasiado grandes")
            return
        lineas = cabecera.decode("latin-1").split("\r\n")
        try:
            metodo, objetivo, version = lineas[0].split(" ")
        except ValueError:
            await self._responder(escritor, 400, "petición inválida")
            return

        if metodo == "CONNECT":
            host, _, puerto_txt = objetivo.rpartition(":")
            host = host.strip("[]")
            es_tunel = True
        else:
            partes = urlsplit(objetivo)
            if partes.scheme != "http" or not partes.hostname:
                await self._responder(escritor, 400, "solo se aceptan URLs http absolutas")
                return
            host, puerto_txt, es_tunel = partes.hostname, str(partes.port or 80), False
        try:
            puerto = int(puerto_txt)
        except ValueError:
            await self._responder(escritor, 400, "puerto inválido")
            return

        ip, motivo = await self._validar(host, puerto)
        if motivo:
            registrar(accion="bloqueado", host=host, puerto=puerto, ip=ip, motivo=motivo)
            await self._responder(escritor, 403, f"bloqueado por el proxy de salida: {motivo}", motivo)
            return

        try:
            up_lector, up_escritor = await asyncio.wait_for(
                asyncio.open_connection(ip, puerto), TIMEOUT_CONEXION_S
            )
        except (OSError, TimeoutError):
            registrar(accion="error_conexion", host=host, puerto=puerto, ip=ip)
            await self._responder(escritor, 502, "no se pudo conectar al destino")
            return
        registrar(accion="permitido", host=host, puerto=puerto, ip=ip, tunel=es_tunel)

        if es_tunel:
            escritor.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            up_escritor.write(self._reescribir_peticion(metodo, objetivo, version, lineas[1:]))
        await escritor.drain()
        await self._tuberia(lector, escritor, up_lector, up_escritor)

    async def _validar(self, host: str, puerto: int) -> tuple[str | None, str | None]:
        """Devuelve (ip_validada, None) o (ip_culpable, motivo) si se bloquea."""
        try:
            ips = await asyncio.wait_for(self.resolver(host, puerto), TIMEOUT_CONEXION_S)
        except (OSError, TimeoutError, UnicodeError):
            return None, "dns_fallido"
        if not ips:
            return None, "dns_vacio"
        for ip in ips:
            motivo = self.politica(ip, puerto)
            if motivo:
                return ip, motivo
        return ips[0], None

    @staticmethod
    def _reescribir_peticion(metodo, objetivo, version, cabeceras) -> bytes:
        partes = urlsplit(objetivo)
        ruta = partes.path or "/"
        if partes.query:
            ruta += "?" + partes.query
        filtradas = [
            c
            for c in cabeceras
            if c and c.split(":", 1)[0].strip().lower()
            not in ("connection", "proxy-connection", "keep-alive", "proxy-authorization")
        ]
        lineas = [f"{metodo} {ruta} {version}", *filtradas, "Connection: close", "", ""]
        return "\r\n".join(lineas).encode("latin-1")

    @staticmethod
    async def _tuberia(lector, escritor, up_lector, up_escritor) -> None:
        async def copiar(origen, destino):
            try:
                while datos := await asyncio.wait_for(origen.read(65536), TIMEOUT_INACTIVIDAD_S):
                    destino.write(datos)
                    await destino.drain()
            except (TimeoutError, ConnectionError):
                pass
            finally:
                destino.close()

        await asyncio.gather(copiar(lector, up_escritor), copiar(up_lector, escritor))

    @staticmethod
    async def _responder(escritor, codigo: int, texto: str, motivo: str | None = None) -> None:
        cuerpo = (
            "<!doctype html><title>Bloqueado por QR-Sandbox</title>"
            f"<h1>{codigo}</h1><p>{texto}</p>"
        ).encode()
        cabeceras = [
            f"HTTP/1.1 {codigo} QR-Sandbox",
            "Content-Type: text/html; charset=utf-8",
            f"Content-Length: {len(cuerpo)}",
            "Connection: close",
        ]
        if motivo:
            cabeceras.append(f"X-QRSandbox-Bloqueo: {motivo}")
        escritor.write(("\r\n".join(cabeceras) + "\r\n\r\n").encode() + cuerpo)
        await escritor.drain()


async def servir(host: str = "0.0.0.0", puerto: int = 3128, proxy: ProxyEgreso | None = None):
    proxy = proxy or ProxyEgreso()
    return await asyncio.start_server(proxy.atender, host, puerto, limit=MAX_CABECERAS)


async def _main() -> None:
    puerto = int(os.environ.get("PROXY_PUERTO", "3128"))
    servidor = await servir(puerto=puerto)
    registrar(accion="inicio", puerto=puerto)
    async with servidor:
        await servidor.serve_forever()


if __name__ == "__main__":
    asyncio.run(_main())
