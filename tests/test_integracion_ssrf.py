"""Fase 2 (aceptación, integración): SSRF, red aislada, seccomp y perfiles con Docker real.

Requiere el stack levantado (`make up`: proxy + red `qrsandbox_sandbox`), la imagen del
worker e internet. Correr con `make test-int`.
"""

import json
import time

import pytest

docker = pytest.importorskip("docker")

from qrsandbox.orquestador.ejecutor import ETIQUETA, SECCOMP_WORKER, ConfigWorker, ejecutar

pytestmark = pytest.mark.integracion
RED = ConfigWorker().red
IMAGEN = ConfigWorker().imagen


@pytest.fixture(scope="module")
def cliente():
    try:
        c = docker.from_env()
        c.images.get(IMAGEN)
        c.networks.get(RED)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"falta el stack (make up): {e}")
    return c


@pytest.fixture(scope="module")
def proxy(cliente):
    contenedores = cliente.containers.list(filters={"label": "com.docker.compose.service=proxy"})
    if not contenedores:
        pytest.skip("proxy no está corriendo (make up)")
    return contenedores[0]


def log_proxy(proxy, desde: float) -> list[dict]:
    crudo = proxy.logs(since=int(desde) - 1, stdout=True, stderr=False).decode()
    entradas = []
    for linea in crudo.splitlines():
        try:
            e = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if e.get("t", 0) >= desde - 0.5:
            entradas.append(e)
    return entradas


CASOS_SSRF = [
    ("http://127.0.0.1/", {"127.0.0.1"}),
    ("http://169.254.169.254/latest/meta-data/", {"169.254.169.254"}),
    ("http://10.0.0.1/", {"10.0.0.1"}),
    ("http://10.0.0.1.nip.io/", {"10.0.0.1"}),  # nombre público que resuelve a IP privada
    ("http://localtest.me/", {"127.0.0.1", "::1"}),  # idem, a loopback (A y AAAA)
    # Redirección desde un sitio público hacia una IP privada: el salto se revalida.
    # (httpbin.org/httpbingo.org responden 403 a este uso; httpbin.dev sí redirige.
    # El caso determinista, sin internet, está en tests/test_proxy.py.)
    ("https://httpbin.dev/redirect-to?url=http%3A%2F%2F10.0.0.1%2F", {"10.0.0.1"}),
]


@pytest.mark.parametrize("perfil", ["endurecido", "gvisor"])
@pytest.mark.parametrize(("url", "ips_internas"), CASOS_SSRF)
def test_ssrf_bloqueado(cliente, proxy, perfil, url, ips_internas):
    desde = time.time()
    r = ejecutar(url, ConfigWorker(perfil=perfil), cliente)
    log = log_proxy(proxy, desde)

    bloqueos = [e for e in log if e["accion"] == "bloqueado" and e.get("ip") in ips_internas]
    assert bloqueos, f"el proxy no registró el bloqueo de {ips_internas}: {log}"
    assert not [e for e in log if e["accion"] == "permitido" and e.get("ip") in ips_internas]
    # La página interna nunca se cargó: el worker ve el error del proxy.
    assert any("bloqueado" in e.get("mensaje", "") for e in r.eventos if e["tipo"] == "error")
    assert r.contenedor_eliminado
    assert r.perfil == perfil


def test_red_sandbox_sin_salida_directa_ni_acceso_al_host(cliente):
    """Aunque el código del worker se comprometa, solo puede hablar con el proxy."""
    script = """
import socket
for h, p in [("1.1.1.1", 443), ("8.8.8.8", 53), ("172.31.250.1", 8000), ("172.31.250.1", 22)]:
    try:
        socket.create_connection((h, p), 3).close(); print("CONECTA", h, p)
    except OSError:
        print("falla", h, p)
socket.create_connection(("172.31.250.2", 3128), 3).close(); print("proxy-ok")
"""
    salida = cliente.containers.run(
        IMAGEN, ["-c", script], entrypoint="python", network=RED, remove=True, runtime="runc"
    ).decode()
    assert "CONECTA" not in salida, salida
    assert "proxy-ok" in salida


PTRACE = "import ctypes; print(ctypes.CDLL(None, use_errno=True).ptrace(0, 0, 0, 0))"


def test_seccomp_propio_bloquea_ptrace(cliente):
    """ptrace(PTRACE_TRACEME) funciona con el seccomp por defecto de Docker, no con el nuestro."""

    def correr(opts):
        return cliente.containers.run(
            IMAGEN, ["-c", PTRACE], entrypoint="python", network="none",
            remove=True, security_opt=opts,
        ).decode().strip()

    assert correr([]) == "0"  # perfil por defecto de Docker: permitido
    assert correr([f"seccomp={SECCOMP_WORKER}"]) == "-1"  # el nuestro: EPERM


def test_gvisor_ignora_el_seccomp_oci(cliente):
    """Documenta (para el informe) que con runsc nuestro perfil seccomp no se aplica:
    ptrace lo atiende el Sentry de gVisor, no el kernel del host."""
    salida = cliente.containers.run(
        IMAGEN, ["-c", PTRACE], entrypoint="python", network="none", remove=True,
        runtime="runsc", security_opt=[f"seccomp={SECCOMP_WORKER}"],
    ).decode().strip()
    assert salida == "0"


@pytest.mark.parametrize("perfil", ["basico", "endurecido", "gvisor"])
def test_perfiles_analizan_example_com(cliente, perfil):
    r = ejecutar("https://example.com", ConfigWorker(perfil=perfil), cliente)
    assert r.error is None, r.error
    assert r.perfil == perfil and r.aviso_runtime is None
    assert r.resultado.titulo == "Example Domain"
    assert r.frames >= 1 and r.eventos_descartados == 0
    assert r.metricas["frames_rechazados"] == 0
    assert r.contenedor_eliminado
    assert cliente.containers.list(all=True, filters={"label": ETIQUETA}) == []


def test_worker_sin_proxy_no_navega(cliente):
    """Falla cerrado: si falta la config del proxy, el worker se niega a navegar."""
    c = cliente.containers.run(IMAGEN, ["https://example.com"], network="none", detach=True)
    try:
        assert c.wait(timeout=30)["StatusCode"] == 3
        assert b"falta QRS_PROXY" in c.logs(stdout=True, stderr=False)
    finally:
        c.remove(force=True)


def test_recodificador_corre_como_nobody_sin_acceso_al_socket(cliente):
    orq = cliente.containers.list(filters={"label": "com.docker.compose.service=orquestador"})
    if not orq:
        pytest.skip("orquestador no está corriendo")
    script = """
from qrsandbox.orquestador.recodificador import Recodificador
import io
from PIL import Image
b = io.BytesIO(); Image.new("RGB", (8, 8)).save(b, format="JPEG")
r = Recodificador(); assert r.recodificar(b.getvalue())
status = open(f"/proc/{r._proc.pid}/status").read()
print([l for l in status.splitlines() if l.startswith(("Uid:", "Groups:"))])
r.cerrar()
"""
    codigo, salida = orq[0].exec_run(["python", "-c", script])
    texto = salida.decode()
    assert codigo == 0, texto
    assert "Uid:\\t65534\\t65534" in texto
    assert "'Groups:\\t '" in texto  # sin grupos suplementarios (ni el de docker)
    codigo, salida = orq[0].exec_run(
        ["python", "-c", "open('/var/run/docker.sock')"], user="65534:65534"
    )
    assert codigo != 0 and b"PermissionError" in salida
