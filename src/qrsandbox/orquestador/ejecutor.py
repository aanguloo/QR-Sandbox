"""Lanza un worker efímero por análisis y recoge su salida validada.

Este es el ÚNICO módulo que habla con Docker (separación de privilegios): la API
no tiene el socket y solo puede pedir "analizar esta URL".

Perfiles de aislamiento (para poder compararlos en el Experimento 2):
- `basico`:     Docker por defecto (runc + seccomp por defecto). Solo para comparar.
- `endurecido`: runc + UID sin privilegios, sin capabilities, no-new-privileges,
                seccomp propio, FS de solo lectura, límites de memoria/CPU/procesos.
- `gvisor`:     `endurecido` + runtime `runsc` (kernel en espacio de usuario).
Si se pide `gvisor` y `runsc` no está disponible, se cae a `endurecido` y queda
registrado en el resultado (`aviso_runtime`).
En TODOS los perfiles el worker está en la red interna `sandbox`, cuya única salida
es el proxy anti-SSRF, y tiene timeout y borrado garantizado.
"""

import base64
import binascii
import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from qrsandbox.comun.esquemas import EvCaptura, EvFin, ResultadoAnalisis, ResultadoWorker
from qrsandbox.orquestador.filtro import FiltroEventos
from qrsandbox.orquestador.lector import LectorEventos
from qrsandbox.orquestador.recodificador import Recodificador

ETIQUETA = "qrsandbox.worker"
MAX_CAPTURA_BYTES = 200_000
JPEG_MAGIC = b"\xff\xd8\xff"
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "3"))
PERFILES = ("basico", "endurecido", "gvisor")

# Perfil seccomp del worker (generado por scripts/generar_seccomp.py).
SECCOMP_WORKER = json.dumps(
    json.loads(resources.files("qrsandbox.orquestador").joinpath("seccomp_worker.json").read_text())
)

# Límite global de workers concurrentes (anti-DoS del host).
_cupos = threading.BoundedSemaphore(MAX_WORKERS)

AlEvento = Callable[[dict], None]


@dataclass(frozen=True)
class ConfigWorker:
    imagen: str = "qrsandbox-worker:dev"
    perfil: str = "gvisor"
    # Red interna creada por docker compose; la única salida es el proxy (IP fija).
    red: str = "qrsandbox_sandbox"
    proxy: str = "http://172.31.250.2:3128"
    memoria: str = "512m"
    cpus: float = 1.0
    pids: int = 256
    timeout_s: float = 20.0

    @classmethod
    def desde_entorno(cls) -> "ConfigWorker":
        perfil = os.environ.get("WORKER_PERFIL", cls.perfil)
        if perfil not in PERFILES:
            raise ValueError(f"WORKER_PERFIL inválido: {perfil}")
        return cls(
            imagen=os.environ.get("WORKER_IMAGEN", cls.imagen),
            perfil=perfil,
            red=os.environ.get("WORKER_RED", cls.red),
            proxy=os.environ.get("WORKER_PROXY", cls.proxy),
        )


def resolver_perfil(cliente, pedido: str) -> tuple[str, str | None]:
    """Devuelve (perfil_efectivo, aviso). Detecta si gVisor está disponible."""
    if pedido != "gvisor":
        return pedido, None
    try:
        runtimes = cliente.info().get("Runtimes", {})
    except APIError:
        runtimes = {}
    if "runsc" not in runtimes:
        return "endurecido", "runsc (gVisor) no disponible: se usó runc endurecido"
    return "gvisor", None


def validar_captura(ev: EvCaptura) -> bytes | None:
    """Chequeo previo y barato del frame tainted: base64, magic bytes JPEG y tamaño.

    Si pasa, igual se re-codifica en el proceso aislado (`Recodificador`).
    """
    try:
        datos = base64.b64decode(ev.jpeg_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(datos) > MAX_CAPTURA_BYTES or not datos.startswith(JPEG_MAGIC):
        return None
    return datos


def parametros_contenedor(config: ConfigWorker, perfil: str, url: str, nombre: str) -> dict:
    p = {
        "image": config.imagen,
        # Lista de argumentos, sin shell: la URL no puede inyectar comandos.
        "command": [url],
        "name": nombre,
        "labels": {ETIQUETA: "1", "qrsandbox.perfil": perfil},
        "detach": True,
        "network": config.red,
        "environment": {"QRS_PROXY": config.proxy},
    }
    if perfil == "basico":
        return p  # valores por defecto de Docker (línea base del Experimento 2)
    p.update(
        runtime="runsc" if perfil == "gvisor" else "runc",
        user="10001:10001",  # sin privilegios
        cap_drop=["ALL"],  # ninguna capability de Linux
        security_opt=[
            "no-new-privileges:true",  # setuid/file caps no dan privilegios
            f"seccomp={SECCOMP_WORKER}",  # perfil propio, más estricto que el de Docker
        ],
        read_only=True,  # FS raíz de solo lectura...
        tmpfs={"/tmp": "rw,nosuid,nodev,size=128m"},  # ...salvo /tmp, en memoria
        mem_limit=config.memoria,
        memswap_limit=config.memoria,  # sin swap extra
        nano_cpus=int(config.cpus * 1e9),
        pids_limit=config.pids,  # anti fork-bomb
    )
    return p


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


def _lanzar(cliente, config, perfil, url, nombre):
    """Crea el contenedor; si runsc falla al arrancar, reintenta con runc endurecido."""
    try:
        params = parametros_contenedor(config, perfil, url, nombre)
        return cliente.containers.run(**params), perfil, None
    except APIError as e:
        if perfil != "gvisor" or "runsc" not in str(e).lower():
            raise
        try:
            cliente.containers.get(nombre).remove(force=True)
        except NotFound:
            pass
        aviso = "runsc falló al arrancar el worker: se usó runc endurecido"
        params = parametros_contenedor(config, "endurecido", url, nombre)
        return cliente.containers.run(**params), "endurecido", aviso


def ejecutar(
    url: str,
    config: ConfigWorker | None = None,
    cliente=None,
    al_evento: AlEvento | None = None,
) -> ResultadoAnalisis:
    """Analiza `url` en un worker efímero.

    `al_evento` (opcional) recibe cada evento aceptado apenas llega: es el gancho para el
    canal en vivo (SSE) de la Fase 5. Para capturas recibe {"tipo": "captura", "jpeg": bytes}
    con el JPEG ya re-codificado.
    """
    config = config or ConfigWorker.desde_entorno()
    cliente = cliente or docker.from_env()
    id_analisis = uuid.uuid4().hex[:12]
    nombre = f"qrs-worker-{id_analisis}"
    lector = LectorEventos()
    filtro = FiltroEventos()
    eventos: list[dict] = []
    resultado: ResultadoWorker | None = None
    captura: bytes | None = None
    frames = bytes_frames = 0
    codigo_salida = error = None
    expiro = threading.Event()
    contenedor = None
    perfil, aviso = resolver_perfil(cliente, config.perfil)
    t0 = time.monotonic()
    t_arranque_ms = None

    def matar() -> None:
        expiro.set()
        try:
            contenedor.kill()
        except (NotFound, APIError, AttributeError):
            pass

    def publicar(evento: dict) -> None:
        if al_evento is not None:
            al_evento(evento)

    with _cupos, Recodificador() as recodificador:
        temporizador = threading.Timer(config.timeout_s, matar)
        try:
            contenedor, perfil, aviso_lanzar = _lanzar(cliente, config, perfil, url, nombre)
            aviso = aviso or aviso_lanzar
            t_arranque_ms = int((time.monotonic() - t0) * 1000)
            temporizador.start()
            flujo = contenedor.logs(stream=True, follow=True, stdout=True, stderr=False)
            for lote in _con_cierre(flujo, lector):
                for ev in lote:
                    if not filtro.admitir(ev.tipo):
                        continue
                    if isinstance(ev, EvCaptura):
                        datos = validar_captura(ev)
                        limpio = recodificador.recodificar(datos) if datos else None
                        if limpio is None:
                            lector.descartados += 1
                            continue
                        captura = limpio  # la última válida es la captura final
                        frames += 1
                        bytes_frames += len(limpio)
                        publicar({"tipo": "captura", "t_ms": ev.t_ms, "jpeg": limpio})
                        continue
                    if isinstance(ev, EvFin):
                        resultado = ev.resultado
                    evento = ev.model_dump(mode="json")
                    eventos.append(evento)
                    publicar(evento)
                if lector.excedido:
                    # Salida desmedida: posible worker comprometido intentando DoS.
                    matar()
                    break
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
                except (NotFound, APIError):
                    pass
        metricas = {
            "arranque_ms": t_arranque_ms,
            "recodificacion_ms_total": round(recodificador.ms_total, 1),
            "recodificacion_ms_por_frame": round(recodificador.ms_total / max(1, frames), 1),
            "frames_rechazados": recodificador.rechazados,
            "recodificador_reinicios": recodificador.reinicios,
            "recodificador_aislado": recodificador.aislado,
            "bytes_frames": bytes_frames,
            "bytes_salida_worker": lector.bytes_totales,
        }

    timeout = expiro.is_set() and not lector.excedido
    return ResultadoAnalisis(
        id=id_analisis,
        url=url,
        runtime="runsc" if perfil == "gvisor" else "runc",
        perfil=perfil,
        perfil_pedido=config.perfil,
        aviso_runtime=aviso,
        duracion_ms=int((time.monotonic() - t0) * 1000),
        codigo_salida=codigo_salida,
        timeout=timeout,
        salida_excedida=lector.excedido,
        eventos=eventos,
        eventos_descartados=lector.descartados,
        descartados_tasa=filtro.descartados_tasa,
        agrupados=dict(filtro.agrupados),
        frames=frames,
        metricas=metricas,
        resultado=resultado,
        captura_jpeg_b64=base64.b64encode(captura).decode("ascii") if captura else None,
        contenedor_eliminado=_no_existe(cliente, nombre),
        error=error or ("timeout del worker" if timeout else None),
    )


def _con_cierre(flujo, lector: LectorEventos):
    """Pasa cada trozo de stdout por el lector; al final procesa el resto del buffer."""
    for trozo in flujo:
        yield lector.alimentar(trozo)
        if lector.excedido:
            return
    yield lector.cerrar()


def _no_existe(cliente, nombre: str) -> bool:
    try:
        cliente.containers.get(nombre)
        return False
    except NotFound:
        return True
