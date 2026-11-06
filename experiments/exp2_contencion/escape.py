"""Corre DENTRO del contenedor del worker: simula un worker COMPROMETIDO.

Supone que un exploit contra Chromium ya le dio al atacante ejecución de código en el
contenedor, y prueba qué puede hacer desde ahí con cada perfil de aislamiento. Imprime una
línea JSON por prueba: {"prueba", "bloqueado": bool, "detalle"}.

Todas las pruebas tienen topes para no dañar el equipo anfitrión (máx. 1,5 GB de memoria,
máx. 1500 procesos, 200 MB en disco) y limpian lo que crean.
"""

import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)


VERSION_KERNEL = Path("/proc/version").read_text().strip()
EN_GVISOR = "gvisor" in VERSION_KERNEL.lower()


def informar(prueba, bloqueado, detalle, contenido=False):
    """`contenido`: la operación "funciona", pero la atiende el kernel de gVisor (Sentry),
    no el del anfitrión: no es un escape, aunque tampoco un bloqueo."""
    print(json.dumps({"prueba": prueba, "bloqueado": bool(bloqueado), "contenido": bool(contenido),
                      "detalle": str(detalle)[:200]}), flush=True)


def permitido(prueba, detalle="permitido"):
    if EN_GVISOR:
        informar(prueba, False, f"{detalle}, pero dentro del kernel de gVisor (no llega al anfitrión)", True)
    else:
        informar(prueba, False, detalle)


def prueba(nombre):
    def decorador(f):
        def envoltura():
            try:
                f()
            except Exception as e:  # noqa: BLE001
                informar(nombre, True, f"{type(e).__name__}: {e}")
        envoltura.nombre = nombre
        return envoltura
    return decorador


@prueba("escribir en el sistema de archivos raíz")
def fs_raiz():
    with open("/usr/qrsandbox-escape", "w") as f:
        f.write("x")
    os.remove("/usr/qrsandbox-escape")
    informar("escribir en el sistema de archivos raíz", False, "se pudo escribir en /usr")


@prueba("llenar /tmp con 200 MB")
def tmp_grande():
    ruta, escritos = "/tmp/relleno", 0
    try:
        with open(ruta, "wb") as f:
            for _ in range(200):
                f.write(b"\0" * 1024 * 1024)
                f.flush()
                escritos += 1
        informar("llenar /tmp con 200 MB", False, f"escribió {escritos} MB")
    except OSError as e:
        informar("llenar /tmp con 200 MB", True, f"se detuvo en {escritos} MB ({e.strerror})")
    finally:
        if os.path.exists(ruta):
            os.remove(ruta)


HIJO_MEMORIA = """
import sys
bloques = []
for i in range(15):
    bloques.append(bytearray(100 * 1024 * 1024))
    print((i + 1) * 100, flush=True)
"""


@prueba("reservar 1,5 GB de memoria")
def memoria():
    p = subprocess.run([sys.executable, "-c", HIJO_MEMORIA], check=False, capture_output=True,
                       text=True, timeout=60)
    alcanzado = (p.stdout.split() or ["0"])[-1]
    if p.returncode == 0:
        informar("reservar 1,5 GB de memoria", False, f"reservó {alcanzado} MB")
    else:
        causa = "matado por el límite de memoria (OOM)" if p.returncode in (-9, 137) else f"código {p.returncode}"
        informar("reservar 1,5 GB de memoria", True, f"{causa} tras {alcanzado} MB")


@prueba("fork bomb (hasta 1500 procesos)")
def procesos():
    hijos = []
    try:
        for _ in range(1500):
            pid = os.fork()
            if pid == 0:
                time.sleep(20)
                os._exit(0)
            hijos.append(pid)
        informar("fork bomb (hasta 1500 procesos)", False, f"creó {len(hijos)} procesos")
    except OSError as e:
        informar("fork bomb (hasta 1500 procesos)", True, f"se detuvo en {len(hijos)} procesos ({e.strerror})")
    finally:
        for pid in hijos:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass


HIJO_CPU = "import time\nfin=time.time()+1.5\nn=0\nwhile time.time()<fin: n+=1\nprint(n)"


@prueba("acaparar CPU con 4 procesos")
def cpu():
    uno = int(subprocess.run([sys.executable, "-c", HIJO_CPU], check=False, capture_output=True,
                             text=True).stdout)
    procs = [subprocess.Popen([sys.executable, "-c", HIJO_CPU], stdout=subprocess.PIPE, text=True) for _ in range(4)]
    total = sum(int(p.communicate()[0]) for p in procs)
    nucleos = total / uno
    informar("acaparar CPU con 4 procesos", nucleos < 1.5, f"obtuvo ~{nucleos:.1f} núcleos")


@prueba("ptrace (inspeccionar procesos)")
def ptrace():
    r = libc.ptrace(0, 0, 0, 0)
    if r != 0:
        informar("ptrace (inspeccionar procesos)", True, "EPERM")
    else:
        permitido("ptrace (inspeccionar procesos)")


@prueba("unshare: crear user namespace")
def unshare():
    os.unshare(os.CLONE_NEWUSER)
    permitido("unshare: crear user namespace")


@prueba("mount (montar un sistema de archivos)")
def montar():
    r = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
    informar("mount (montar un sistema de archivos)", r != 0, os.strerror(ctypes.get_errno()) if r else "permitido")


@prueba("socket crudo (CAP_NET_RAW)")
def socket_crudo():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.close()
    informar("socket crudo (CAP_NET_RAW)", False, "permitido")


@prueba("volverse root (setuid 0)")
def setuid():
    if os.getuid() == 0:
        informar("volverse root (setuid 0)", False, "ya corre como root")
        return
    os.setuid(0)
    informar("volverse root (setuid 0)", False, "permitido")


@prueba("io_uring (superficie de exploits del kernel)")
def io_uring():
    r = libc.syscall(425, 1, None)  # io_uring_setup en x86_64
    errno = ctypes.get_errno()
    informar("io_uring (superficie de exploits del kernel)", r < 0, os.strerror(errno) if r < 0 else "permitido")


@prueba("ver el kernel del anfitrión")
def kernel():
    # Con gVisor se ve un kernel simulado: el atacante no sabe qué kernel real atacar.
    informar("ver el kernel del anfitrión", EN_GVISOR, VERSION_KERNEL[:120])


@prueba("socket de Docker")
def docker_sock():
    existe = os.path.exists("/var/run/docker.sock")
    informar("socket de Docker", not existe, "presente" if existe else "no existe en el contenedor")


def conectar(nombre, host, puerto, nota=""):
    @prueba(nombre)
    def f():
        try:
            socket.create_connection((host, puerto), 3).close()
            informar(nombre, False, f"conectó{nota}")
        except OSError as e:
            informar(nombre, True, e.strerror or type(e).__name__)
    return f


PRUEBAS = [
    fs_raiz, tmp_grande, memoria, procesos, cpu, ptrace, unshare, montar, socket_crudo,
    setuid, io_uring, kernel, docker_sock,
    conectar("internet directo (1.1.1.1:443)", "1.1.1.1", 443),
    conectar("metadatos de la nube (169.254.169.254)", "169.254.169.254", 80),
    conectar("anfitrión vía gateway (172.31.250.1:22)", "172.31.250.1", 22),
    # El proxy es la única salida permitida: que conecte es lo esperado.
    conectar("proxy de salida (172.31.250.2:3128)", "172.31.250.2", 3128,
             " (esperado: es la única salida, y filtra destinos)"),
]

DESTRUCTIVAS = {"memoria": memoria, "procesos": procesos}  # cada una en su propio contenedor

if __name__ == "__main__":
    pedidas = sys.argv[1:]
    for p in ([DESTRUCTIVAS[n] for n in pedidas] if pedidas else
              [p for p in PRUEBAS if p not in DESTRUCTIVAS.values()]):
        p()
