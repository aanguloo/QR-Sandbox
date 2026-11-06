"""Análisis en curso: ejecución en segundo plano y canal en vivo (SSE).

Flujo (separación de privilegios):
    worker --stdout--> orquestador (valida, re-codifica frames) --NDJSON--> API (re-valida)
    --SSE--> navegador
El worker no tiene ninguna conexión con la API ni con el navegador.

Lo que llega del orquestador ya pasó el esquema cerrado, pero se valida de nuevo aquí
(defensa en profundidad: un bug allá no debe convertirse en un bug acá). Al navegador
solo llegan: eventos con esquema fijo, frames JPEG (bytes) y el veredicto. Nunca HTML ni
scripts de la página analizada.
"""

import base64
import binascii
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx
from pydantic import ValidationError

from qrsandbox.comun.esquemas import ADAPTADOR_EVENTO, ResultadoAnalisis
from qrsandbox.senales.dominio import partes_host
from qrsandbox.senales.estaticas import ResultadoEstatico, analizar_url
from qrsandbox.veredicto.motor import evaluar

ORQUESTADOR_URL = os.environ.get("ORQUESTADOR_URL", "http://127.0.0.1:9000")
ID_VALIDO = re.compile(r"^[0-9a-f]{32}$")  # 128 bits: el id funciona como capacidad
MAX_ANALISIS = 100  # cada uno guarda hasta MAX_FOTOS imágenes (~50 KB c/u)
MAX_EVENTOS = 600
MAX_FOTOS = 8  # "fotos paso a paso": momentos clave del análisis
INTERVALO_FOTO_S = 2.5
MAX_LINEA = 400_000
MAX_FRAME = 200_000
DECIMALES_UBICACION = 3


@dataclass
class EventoVivo:
    seq: int
    tipo: str  # evento | estatico | foto | fin | fallo ("error" choca con EventSource)
    datos: dict


@dataclass
class Analisis:
    id: str
    url: str
    lat: float | None
    lon: float | None
    estado: str = "en_curso"  # en_curso | terminado | error
    resultado: dict | None = None
    frame: bytes | None = None
    frame_seq: int = 0
    captura: bytes | None = None
    descartados: int = 0
    creado: float = field(default_factory=time.monotonic)
    # Fotos paso a paso: (t_ms, etiqueta, jpeg). Las etiquetas pueden incluir un host
    # elegido por el atacante: el navegador las muestra con textContent.
    fotos: list[tuple[int, str, bytes]] = field(default_factory=list)
    _etiqueta_pendiente: str | None = None
    _ultima_foto: float = 0.0
    _eventos: list[EventoVivo] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def publicar(self, tipo: str, datos: dict) -> None:
        with self._lock:
            if len(self._eventos) >= MAX_EVENTOS and tipo not in ("fin", "fallo"):
                self.descartados += 1
                return
            self._eventos.append(EventoVivo(len(self._eventos), tipo, datos))

    def poner_frame(self, jpeg: bytes, t_ms: int = 0) -> None:
        """Frame del screencast. Algunos se guardan como "foto paso a paso": el primero, el
        siguiente a cada navegación/redirección, y uno cada INTERVALO_FOTO_S. Se reserva el
        último lugar para la captura final."""
        ahora = time.monotonic()
        with self._lock:
            self.frame = jpeg
            self.frame_seq += 1
            etiqueta = None
            if not self.fotos:
                etiqueta = "Primera imagen"
            elif self._etiqueta_pendiente:
                etiqueta = self._etiqueta_pendiente
            elif ahora - self._ultima_foto >= INTERVALO_FOTO_S:
                etiqueta = f"A los {t_ms / 1000:.0f} s"
            if etiqueta is None or len(self.fotos) >= MAX_FOTOS - 1:
                return
            self._etiqueta_pendiente = None
            self._ultima_foto = ahora
            self.fotos.append((t_ms, etiqueta, jpeg))
            n = len(self.fotos) - 1
        self.publicar("foto", self.foto_publica(n))

    def marcar_momento(self, etiqueta: str) -> None:
        """La próxima imagen que llegue se guarda como foto con esta etiqueta."""
        with self._lock:
            self._etiqueta_pendiente = etiqueta[:120]

    def foto_final(self, jpeg: bytes) -> None:
        with self._lock:
            if self.fotos and self.fotos[-1][2] == jpeg:
                # La última foto ya es la captura final: se marca, sin duplicar la imagen.
                t_ms, etiqueta, _ = self.fotos[-1]
                if not etiqueta.endswith("captura final"):
                    self.fotos[-1] = (t_ms, f"{etiqueta} · captura final", jpeg)
                return
            t_ms = self.fotos[-1][0] if self.fotos else 0
            self.fotos.append((t_ms, "Captura final", jpeg))
            n = len(self.fotos) - 1
        self.publicar("foto", self.foto_publica(n))

    def foto_publica(self, n: int) -> dict:
        t_ms, etiqueta, _ = self.fotos[n]
        return {"n": n, "t_ms": t_ms, "etiqueta": etiqueta, "url": f"/analisis/{self.id}/fotos/{n}"}

    def desde(self, seq: int) -> list[EventoVivo]:
        with self._lock:
            return self._eventos[seq:]

    @property
    def terminado(self) -> bool:
        return self.estado != "en_curso"


class AlmacenLleno(Exception):
    pass


class Almacen:
    """Análisis en memoria (acotado). Se descartan primero los más viejos ya terminados."""

    def __init__(self, maximo: int = MAX_ANALISIS):
        self.maximo = maximo
        self._datos: OrderedDict[str, Analisis] = OrderedDict()
        self._lock = threading.Lock()

    def crear(self, url: str, lat: float | None, lon: float | None) -> Analisis:
        if lat is not None:
            # Privacidad: la ubicación se redondea (~110 m) apenas entra.
            lat, lon = round(lat, DECIMALES_UBICACION), round(lon, DECIMALES_UBICACION)
        a = Analisis(secrets.token_hex(16), url, lat, lon)
        with self._lock:
            while len(self._datos) >= self.maximo:
                viejo = next((k for k, v in self._datos.items() if v.terminado), None)
                if viejo is None:
                    raise AlmacenLleno
                del self._datos[viejo]
            self._datos[a.id] = a
        return a

    def obtener(self, id_analisis: str) -> Analisis | None:
        if not ID_VALIDO.match(id_analisis):
            return None
        with self._lock:
            return self._datos.get(id_analisis)


almacen = Almacen()
hilos = ThreadPoolExecutor(max_workers=int(os.environ.get("MAX_ANALISIS_SIMULTANEOS", "4")))


def flujo_orquestador(url: str) -> Iterator[bytes]:
    """Líneas NDJSON del orquestador. Separado para poder simularlo en los tests."""
    with httpx.stream("POST", f"{ORQUESTADOR_URL}/analizar", json={"url": url},
                      timeout=httpx.Timeout(60, connect=5)) as r:
        r.raise_for_status()
        for linea in r.iter_lines():
            if linea:
                yield linea.encode() if isinstance(linea, str) else linea


def jpeg_valido(b64: object) -> bytes | None:
    if not isinstance(b64, str) or len(b64) > MAX_FRAME * 4 // 3 + 8:
        return None
    try:
        datos = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return datos if datos.startswith(b"\xff\xd8\xff") and len(datos) <= MAX_FRAME else None


def _resumen_estatico(e: ResultadoEstatico) -> dict:
    return {
        "datos": e.datos,
        "hallazgos": [h.a_dict() for h in e.hallazgos],
    }


def ejecutar_analisis(a: Analisis, log, listas, red) -> None:
    """Corre un análisis completo publicando eventos en vivo. Nunca lanza excepciones."""
    try:
        with ThreadPoolExecutor(max_workers=1) as aux:
            futuro = aux.submit(analizar_url, a.url, listas=listas, red=red)
            futuro.add_done_callback(
                lambda f: f.exception() is None and a.publicar("estatico", _resumen_estatico(f.result()))
            )
            crudo = None
            for linea in flujo_orquestador(a.url):
                if len(linea) > MAX_LINEA:
                    continue
                try:
                    d = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                tipo = d.get("tipo") if isinstance(d, dict) else None
                if tipo == "resultado":
                    crudo = d.get("datos")
                elif tipo == "captura":
                    if jpeg := jpeg_valido(d.get("jpeg_b64")):
                        t_ms = d.get("t_ms") if isinstance(d.get("t_ms"), int) else 0
                        a.poner_frame(jpeg, max(0, min(t_ms, 120_000)))
                else:
                    try:
                        ev = ADAPTADOR_EVENTO.validate_python(d)
                    except ValidationError:
                        a.descartados += 1
                        continue
                    if ev.tipo == "navegacion":
                        a.marcar_momento(f"Llegó a {partes_host(ev.url).host}")
                    elif ev.tipo == "redireccion":
                        a.marcar_momento(f"Redirigiendo a {partes_host(ev.hacia).host}")
                    if ev.tipo not in ("fin", "captura"):
                        a.publicar("evento", ev.model_dump(mode="json"))
            estatico = futuro.result()
        if crudo is None:
            raise RuntimeError("el orquestador no entregó un resultado")
        r = ResultadoAnalisis.model_validate(crudo)

        estatico_final = None
        final = r.resultado.url_final if r.resultado else None
        if final and partes_host(final).host != estatico.partes.host:
            estatico_final = analizar_url(final, listas=listas, red=red)
        consulta_log = log.consultar(a.url, a.lat, a.lon) if a.lat is not None else None

        a.captura = jpeg_valido(r.captura_jpeg_b64) or a.frame
        if a.captura:
            a.foto_final(a.captura)
        salida = r.model_dump(mode="json", exclude={"captura_jpeg_b64"})
        salida["fotos"] = [a.foto_publica(n) for n in range(len(a.fotos))]
        salida["id"] = a.id  # el id público es el de la API (el del orquestador es interno)
        salida["url"] = a.url
        salida["captura_url"] = f"/analisis/{a.id}/captura" if a.captura else None
        salida["veredicto"] = evaluar(estatico, estatico_final, r, consulta_log, listas=listas)
        salida["senales_estaticas"] = {
            "inicial": estatico.datos,
            "final": estatico_final.datos if estatico_final else None,
        }
        salida["log"] = consulta_log
        a.resultado = salida
        a.estado = "terminado"
        a.publicar("fin", salida)
    except (httpx.HTTPError, httpx.InvalidURL):
        a.estado = "error"
        a.publicar("fallo", {"mensaje": "el sandbox no está disponible; intenta de nuevo"})
    except Exception:  # noqa: BLE001 - un análisis nunca puede quedar "en curso" para siempre
        a.estado = "error"
        a.publicar("fallo", {"mensaje": "el análisis falló"})
