"""Lanza un worker efímero por análisis y recoge su salida validada.

Este es el ÚNICO módulo que habla con Docker (separación de privilegios): la API
no tiene el socket y solo puede pedir "analizar esta URL".
"""

import base64
import binascii
import os
import threading
import time
import uuid
from dataclasses import dataclass

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from qrsandbox.comun.esquemas import EvCaptura, EvFin, ResultadoAnalisis, ResultadoWorker
from qrsandbox.orquestador.lector import LectorEventos

ETIQUETA = "qrsandbox.worker"
MAX_CAPTURA_BYTES = 200_000
JPEG_MAGIC = b"\xff\xd8\xff"
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "3"))

# Límite global de workers concurrentes (anti-DoS del host).
_cupos = threading.BoundedSemaphore(MAX_WORKERS)


@dataclass(frozen=True)
class ConfigWorker:
    imagen: str = "qrsandbox-worker:dev"
    runtime: str = "runc"
    red: str = "bridge"  # Fase 2: red interna cuya única salida es el proxy anti-SSRF
    memoria: str = "512m"
    cpus: float = 1.0
    pids: int = 256
    timeout_s: float = 20.0

    @classmethod
    def desde_entorno(cls) -> "ConfigWorker":
        return cls(
            imagen=os.environ.get("WORKER_IMAGEN", cls.imagen),
            runtime=os.environ.get("WORKER_RUNTIME", cls.runtime),
            red=os.environ.get("WORKER_RED", cls.red),
        )


def validar_captura(ev: EvCaptura) -> bytes | None:
    """Chequeo mínimo de la captura tainted: base64 válido, magic bytes JPEG y tamaño.

    La re-codificación con Pillow en un proceso aislado llega en la Fase 2.
    """
    try:
        datos = base64.b64decode(ev.jpeg_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(datos) > MAX_CAPTURA_BYTES or not datos.startswith(JPEG_MAGIC):
        return None
    return datos


def _parametros_contenedor(config: ConfigWorker, url: str, nombre: str) -> dict:
    return {
        "image": config.imagen,
        # Lista de argumentos, sin shell: la URL no puede inyectar comandos.
        "command": [url],
        "name": nombre,
        "labels": {ETIQUETA: "1"},
        "detach": True,
        "runtime": config.runtime,
        "network": config.red,
        "user": "10001:10001",  # sin privilegios
        "cap_drop": ["ALL"],  # ninguna capability de Linux
        "security_opt": ["no-new-privileges:true"],  # setuid no da privilegios
        "read_only": True,  # FS raíz de solo lectura...
        "tmpfs": {"/tmp": "rw,nosuid,nodev,size=128m"},  # ...salvo /tmp, en memoria
        "mem_limit": config.memoria,
        "memswap_limit": config.memoria,  # sin swap extra
        "nano_cpus": int(config.cpus * 1e9),
        "pids_limit": config.pids,  # anti fork-bomb
    }


def limpiar_huerfanos(cliente: docker.DockerClient) -> int:
    """Borra workers que hayan quedado vivos (p. ej. si el orquestador se cayó)."""
    n = 0
    for c in cliente.containers.list(all=True, filters={"label": ETIQUETA}):
        try:
            c.remove(force=True)
            n += 1
        except NotFound:
            pass
    return n


def ejecutar(url: str, config: ConfigWorker | None = None, cliente=None) -> ResultadoAnalisis:
    config = config or ConfigWorker.desde_entorno()
    cliente = cliente or docker.from_env()
    id_analisis = uuid.uuid4().hex[:12]
    nombre = f"qrs-worker-{id_analisis}"
    lector = LectorEventos()
    eventos: list[dict] = []
    resultado: ResultadoWorker | None = None
    captura: bytes | None = None
    codigo_salida = None
    error = None
    expiro = threading.Event()
    contenedor = None
    t0 = time.monotonic()

    def matar() -> None:
        expiro.set()
        try:
            contenedor.kill()
        except (NotFound, APIError):
            pass

    with _cupos:
        temporizador = threading.Timer(config.timeout_s, matar)
        try:
            contenedor = cliente.containers.run(**_parametros_contenedor(config, url, nombre))
            temporizador.start()
            for chunk in contenedor.logs(stream=True, follow=True, stdout=True, stderr=False):
                for ev in lector.alimentar(chunk):
                    if isinstance(ev, EvCaptura):
                        datos = validar_captura(ev)
                        if datos is None:
                            lector.descartados += 1
                        else:
                            captura = datos  # nos quedamos con la última válida
                        continue
                    if isinstance(ev, EvFin):
                        resultado = ev.resultado
                    eventos.append(ev.model_dump(mode="json"))
                if lector.excedido:
                    # Salida desmedida: posible worker comprometido intentando DoS.
                    matar()
                    break
            if not lector.excedido:
                for ev in lector.cerrar():
                    if not isinstance(ev, EvCaptura):
                        eventos.append(ev.model_dump(mode="json"))
            codigo_salida = contenedor.wait(timeout=5).get("StatusCode")
        except ImageNotFound:
            error = f"imagen del worker no encontrada: {config.imagen}"
        except APIError as e:
            error = f"error de Docker: {e.explanation or e}"[:300]
        except Exception as e:  # noqa: BLE001 - el análisis falla, el servicio no
            error = f"error del orquestador: {type(e).__name__}"
        finally:
            temporizador.cancel()
            # El contenedor se destruye SIEMPRE, terminara bien o no.
            if contenedor is not None:
                try:
                    contenedor.remove(force=True)
                except NotFound:
                    pass

    return ResultadoAnalisis(
        id=id_analisis,
        url=url,
        runtime=config.runtime,
        duracion_ms=int((time.monotonic() - t0) * 1000),
        codigo_salida=codigo_salida,
        timeout=expiro.is_set() and not lector.excedido,
        salida_excedida=lector.excedido,
        eventos=eventos,
        eventos_descartados=lector.descartados,
        resultado=resultado,
        captura_jpeg_b64=base64.b64encode(captura).decode("ascii") if captura else None,
        contenedor_eliminado=_no_existe(cliente, nombre),
        error=error or ("timeout del worker" if expiro.is_set() and not lector.excedido else None),
    )


def _no_existe(cliente, nombre: str) -> bool:
    try:
        cliente.containers.get(nombre)
        return False
    except NotFound:
        return True
