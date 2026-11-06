"""Fase 2 (aceptación): el proxy de salida bloquea SSRF.

El proxy corre en proceso, con un DNS simulado: los tests no salen a internet.
"""

import asyncio
import json

import pytest

from qrsandbox.proxy import servidor
from qrsandbox.proxy.politica import motivo_bloqueo
from qrsandbox.proxy.servidor import ProxyEgreso

PUBLICA = "93.184.215.14"  # una IP global cualquiera


@pytest.mark.parametrize(
    ("ip", "motivo"),
    [
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "link_local_metadatos"),
        ("169.254.1.1", "link_local"),
        ("fe80::1%eth0", "link_local"),
        ("10.0.0.1", "privada"),
        ("172.16.5.4", "privada"),
        ("192.168.1.1", "privada"),
        ("fd00::1", "privada"),
        ("100.64.0.1", "no_global"),  # CGNAT
        ("0.0.0.0", "no_especificada"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "privada"),  # reservada
        ("::ffff:127.0.0.1", "ipv6_embebida_loopback"),
        ("::ffff:10.0.0.1", "ipv6_embebida_privada"),
        ("64:ff9b::a9fe:a9fe", "ipv6_embebida_link_local_metadatos"),  # NAT64 de 169.254.169.254
        ("2002:0a00:0001::1", "ipv6_embebida_privada"),  # 6to4 de 10.0.0.1
    ],
)
def test_politica_bloquea_rangos_internos(ip, motivo):
    assert motivo_bloqueo(ip, 80) == motivo


@pytest.mark.parametrize("ip", [PUBLICA, "8.8.8.8", "2606:4700:4700::1111"])
def test_politica_permite_ips_globales(ip):
    assert motivo_bloqueo(ip, 443) is None


@pytest.mark.parametrize("puerto", [22, 25, 3306, 6379, 8080])
def test_politica_bloquea_puertos_no_web(puerto):
    assert motivo_bloqueo(PUBLICA, puerto) == "puerto_no_permitido"


# --- Proxy en proceso -------------------------------------------------------

DNS_FALSO = {
    "localhost": ["127.0.0.1"],
    "rebind.test": ["10.0.0.5"],  # nombre "público" que resuelve a una IP interna
    "mixto.test": [PUBLICA, "10.0.0.1"],  # registro mixto: una buena y una mala
    "metadata.google.internal": ["169.254.169.254"],
}


async def resolver_falso(host, puerto):
    if host in DNS_FALSO:
        return DNS_FALSO[host]
    try:  # IP literal: el resolver real la devuelve tal cual
        import ipaddress

        return [str(ipaddress.ip_address(host))]
    except ValueError:
        raise OSError("NXDOMAIN") from None


async def peticion_cruda(puerto_proxy: int, datos: bytes) -> tuple[int, dict]:
    lector, escritor = await asyncio.open_connection("127.0.0.1", puerto_proxy)
    escritor.write(datos)
    await escritor.drain()
    cabecera = await asyncio.wait_for(lector.readuntil(b"\r\n\r\n"), 5)
    escritor.close()
    lineas = cabecera.decode().split("\r\n")
    cabeceras = {k.lower(): v.strip() for k, v in (ln.split(":", 1) for ln in lineas[1:] if ":" in ln)}
    return int(lineas[0].split(" ")[1]), cabeceras


def con_proxy(prueba, politica=motivo_bloqueo):
    """Levanta el proxy en un puerto libre, corre `prueba(puerto)` y lo apaga."""

    async def correr():
        srv = await servidor.servir("127.0.0.1", 0, ProxyEgreso(resolver_falso, politica))
        puerto = srv.sockets[0].getsockname()[1]
        try:
            return await prueba(puerto)
        finally:
            srv.close()
            await srv.wait_closed()

    return asyncio.run(correr())


@pytest.mark.parametrize(
    ("url", "motivo"),
    [
        ("http://127.0.0.1/", "loopback"),
        ("http://169.254.169.254/latest/meta-data/", "link_local_metadatos"),
        ("http://10.0.0.1/", "privada"),
        ("http://localhost/", "loopback"),
        ("http://rebind.test/", "privada"),
        ("http://mixto.test/", "privada"),
        ("http://metadata.google.internal/", "link_local_metadatos"),
        ("http://[::ffff:127.0.0.1]/", "ipv6_embebida_loopback"),
        ("http://8.8.8.8:22/", "puerto_no_permitido"),
    ],
)
def test_http_hacia_destinos_internos_se_bloquea(url, motivo, capsys):
    host = url.split("/")[2]
    peticion = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    codigo, cabeceras = con_proxy(lambda p: peticion_cruda(p, peticion))
    assert codigo == 403
    assert cabeceras["x-qrsandbox-bloqueo"] == motivo
    log = [json.loads(ln) for ln in capsys.readouterr().out.splitlines()]
    assert log[-1]["accion"] == "bloqueado" and log[-1]["motivo"] == motivo


@pytest.mark.parametrize(
    "objetivo", ["10.0.0.1:443", "127.0.0.1:443", "[::1]:443", "169.254.169.254:443", "rebind.test:443"]
)
def test_connect_hacia_destinos_internos_se_bloquea(objetivo):
    peticion = f"CONNECT {objetivo} HTTP/1.1\r\nHost: {objetivo}\r\n\r\n".encode()
    codigo, _ = con_proxy(lambda p: peticion_cruda(p, peticion))
    assert codigo == 403


def test_redireccion_hacia_ip_privada_se_bloquea(capsys):
    """Un sitio "público" responde 302 -> http://10.0.0.1/. El salto se revalida y se bloquea."""
    import httpx

    async def origen(lector, escritor):
        await lector.readuntil(b"\r\n\r\n")
        escritor.write(
            b"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/admin\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await escritor.drain()
        escritor.close()

    async def prueba(puerto_proxy):
        srv_origen = await asyncio.start_server(origen, "127.0.0.1", 0)
        puerto_origen = srv_origen.sockets[0].getsockname()[1]
        DNS_FALSO["publico.test"] = ["127.0.0.1"]
        permitido["destino"] = ("127.0.0.1", puerto_origen)
        try:
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{puerto_proxy}") as cliente:
                r = await cliente.get(f"http://publico.test:{puerto_origen}/", follow_redirects=True)
                return r
        finally:
            srv_origen.close()

    permitido = {}

    def politica_test(ip, puerto):
        # Solo para el test: el "sitio público" vive en 127.0.0.1:<puerto efímero>.
        if (ip, puerto) == permitido.get("destino"):
            return None
        return motivo_bloqueo(ip, puerto)

    r = con_proxy(prueba, politica_test)
    assert [h.status_code for h in r.history] == [302]
    assert r.status_code == 403
    assert r.headers["x-qrsandbox-bloqueo"] == "privada"
    log = [json.loads(ln) for ln in capsys.readouterr().out.splitlines()]
    assert [e["accion"] for e in log] == ["permitido", "bloqueado"]
    assert log[1]["ip"] == "10.0.0.1"


def test_conexion_http_queda_atada_al_destino_validado():
    """Se fuerza Connection: close y se quitan cabeceras de proxy al reenviar."""
    datos = ProxyEgreso._reescribir_peticion(
        "GET",
        "http://ejemplo.cl/a?b=1",
        "HTTP/1.1",
        ["Host: ejemplo.cl", "Proxy-Connection: keep-alive", "Connection: keep-alive", ""],
    )
    texto = datos.decode()
    assert texto.startswith("GET /a?b=1 HTTP/1.1\r\n")
    assert "keep-alive" not in texto.lower()
    assert "Connection: close" in texto


def test_cabeceras_gigantes_se_rechazan():
    peticion = b"GET http://a.cl/ HTTP/1.1\r\nX: " + b"A" * 20_000 + b"\r\n\r\n"
    codigo, _ = con_proxy(lambda p: peticion_cruda(p, peticion))
    assert codigo == 431
