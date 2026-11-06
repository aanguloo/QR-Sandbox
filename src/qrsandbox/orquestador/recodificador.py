"""Re-codificación aislada de los frames JPEG que manda el worker.

Escenario (clase de RLBox): un frame "JPEG" puede ser un archivo diseñado para explotar
un bug del decodificador de imágenes. Si lo decodificáramos en el orquestador (que tiene
el socket de Docker), un exploit así tomaría el componente más privilegiado.

Por eso cada frame se decodifica en un PROCESO HIJO separado:
- sin privilegios: si el orquestador corre como root, el hijo baja a nobody (65534)
  sin grupos suplementarios, así no puede usar el socket de Docker (root:docker 660);
- con límites del kernel (rlimit): memoria virtual, CPU, sin crear archivos ni procesos;
- con timeout por frame: si se cuelga o muere, se descarta el frame y se relanza.
El hijo valida formato y dimensiones ANTES de decodificar (anti "bomba de píxeles") y
genera un JPEG nuevo desde los píxeles, sin EXIF/ICC ni otros metadatos.

Protocolo por stdin/stdout: [4 bytes largo big-endian][datos] -> [1 byte estado][4 bytes largo][datos].
"""

import os
import select
import struct
import subprocess
import sys
import time
from typing import Self

MAX_ENTRADA = 200_000  # bytes por frame (también lo exige el orquestador antes)
MAX_ANCHO, MAX_ALTO = 1080, 2400
CALIDAD = 70
TIMEOUT_FRAME_S = 3.0
MEMORIA_HIJO = 256 * 1024 * 1024
CPU_HIJO_S = 30
FRAMES_POR_HIJO = 200  # se relanza periódicamente: un hijo envenenado no dura mucho
NOBODY = 65534

OK, ERROR = 0, 1


# --------------------------- proceso hijo ---------------------------------


def _limitar_hijo() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (MEMORIA_HIJO, MEMORIA_HIJO))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_HIJO_S, CPU_HIJO_S))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # no puede escribir archivos
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))  # no puede crear procesos
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def recodificar_bytes(datos: bytes) -> bytes:
    """Decodifica y re-codifica un JPEG. Lanza ValueError si no es aceptable."""
    import io

    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_ANCHO * MAX_ALTO  # Pillow aborta si se excede
    if len(datos) > MAX_ENTRADA or not datos.startswith(b"\xff\xd8\xff"):
        raise ValueError("no es un JPEG aceptable")
    with Image.open(io.BytesIO(datos), formats=["JPEG"]) as img:
        # Image.open solo lee la cabecera: chequeamos dimensiones antes de decodificar.
        if img.width > MAX_ANCHO or img.height > MAX_ALTO or img.width < 1 or img.height < 1:
            raise ValueError("dimensiones fuera de rango")
        img.load()
        rgb = img.convert("RGB")
    # Imagen nueva desde los píxeles crudos: no arrastra EXIF, ICC, comentarios, etc.
    limpia = Image.frombytes("RGB", rgb.size, rgb.tobytes())
    salida = io.BytesIO()
    limpia.save(salida, format="JPEG", quality=CALIDAD)
    return salida.getvalue()


def _leer(n: int) -> bytes:
    datos = sys.stdin.buffer.read(n)
    if len(datos) != n:
        raise EOFError
    return datos


def _bucle_hijo() -> None:
    import PIL.JpegImagePlugin  # noqa: F401 - importar antes de aplicar los límites

    _limitar_hijo()
    salida = sys.stdout.buffer
    while True:
        try:
            (largo,) = struct.unpack(">I", _leer(4))
        except EOFError:
            return
        datos = _leer(largo) if largo <= MAX_ENTRADA else b""
        try:
            resultado, estado = recodificar_bytes(datos), OK
        except Exception:  # noqa: BLE001 - cualquier fallo = frame rechazado
            resultado, estado = b"", ERROR
        salida.write(struct.pack(">BI", estado, len(resultado)) + resultado)
        salida.flush()


# --------------------------- lado del orquestador -------------------------


class Recodificador:
    """Mantiene un proceso hijo aislado y le pasa frames de a uno."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._frames_hijo = 0
        self.aislado = os.geteuid() == 0  # solo root puede bajar a nobody
        self.ok = 0
        self.rechazados = 0
        self.reinicios = 0
        self.ms_total = 0.0

    def _lanzar(self) -> None:
        extra = {}
        if self.aislado:
            extra = {"user": NOBODY, "group": NOBODY, "extra_groups": []}
        self._proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "qrsandbox.orquestador.recodificador"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            # -I (modo aislado): ignora variables PYTHON* y el directorio actual al importar.
            env={"PATH": "/usr/bin:/bin"},
            close_fds=True,
            **extra,
        )
        self._frames_hijo = 0

    def _matar(self) -> None:
        if self._proc is None:
            return
        proc, self._proc = self._proc, None
        try:
            proc.stdin.close()  # cierre ordenado: el hijo termina al leer EOF
            proc.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            # Colgado (o envenenado): SIGKILL. Requiere CAP_KILL en el contenedor del
            # orquestador, porque el hijo corre con otro UID (nobody).
            try:
                proc.kill()
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        finally:
            proc.stdout.close()

    def _leer_exacto(self, n: int, limite: float) -> bytes:
        fd = self._proc.stdout.fileno()
        datos = bytearray()
        while len(datos) < n:
            restante = limite - time.monotonic()
            if restante <= 0 or not select.select([fd], [], [], restante)[0]:
                raise TimeoutError
            trozo = os.read(fd, n - len(datos))
            if not trozo:
                raise EOFError
            datos.extend(trozo)
        return bytes(datos)

    def recodificar(self, datos: bytes) -> bytes | None:
        """Devuelve el JPEG limpio, o None si el frame se rechaza."""
        t0 = time.monotonic()
        try:
            if len(datos) > MAX_ENTRADA or not datos.startswith(b"\xff\xd8\xff"):
                raise ValueError
            if self._proc is None or self._frames_hijo >= FRAMES_POR_HIJO:
                if self._proc is not None:
                    self._matar()
                    self.reinicios += 1
                self._lanzar()
            self._frames_hijo += 1
            self._proc.stdin.write(struct.pack(">I", len(datos)) + datos)
            self._proc.stdin.flush()
            limite = time.monotonic() + TIMEOUT_FRAME_S
            estado, largo = struct.unpack(">BI", self._leer_exacto(5, limite))
            if largo > MAX_ENTRADA * 2:
                raise ValueError
            limpio = self._leer_exacto(largo, limite)
            if estado != OK or not limpio.startswith(b"\xff\xd8\xff"):
                raise ValueError
            self.ok += 1
            return limpio
        except ValueError:
            self.rechazados += 1
            return None
        except (TimeoutError, EOFError, OSError):
            # El hijo se colgó o murió (¿exploit?): se mata y se relanza en el próximo frame.
            self._matar()
            self.reinicios += 1
            self.rechazados += 1
            return None
        finally:
            self.ms_total += (time.monotonic() - t0) * 1000

    def cerrar(self) -> None:
        self._matar()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.cerrar()


if __name__ == "__main__":
    _bucle_hijo()
