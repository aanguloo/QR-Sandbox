"""Lectura y validación de la salida (tainted) del worker.

Es lógica pura (sin Docker) para poder testearla con entradas hostiles.
El worker puede mandar líneas gigantes, JSON roto, tipos inventados o un flujo
infinito; nada de eso debe tumbar al orquestador ni llegar sin validar a la API.
"""

from dataclasses import dataclass, field

from pydantic import ValidationError

from qrsandbox.comun.esquemas import ADAPTADOR_EVENTO, Evento

MAX_LINEA = 300_000  # bytes por línea (la captura en base64 es la más grande)
MAX_TOTAL = 4_000_000  # bytes totales por análisis
MAX_EVENTOS = 1_000  # eventos válidos por análisis


@dataclass
class LectorEventos:
    max_linea: int = MAX_LINEA
    max_total: int = MAX_TOTAL
    max_eventos: int = MAX_EVENTOS
    descartados: int = 0
    bytes_totales: int = 0
    excedido: bool = False  # True => el orquestador debe matar el worker
    _buffer: bytearray = field(default_factory=bytearray)
    _descartando_linea: bool = False  # estamos saltando una línea demasiado larga
    _validos: int = 0

    def alimentar(self, chunk: bytes) -> list[Evento]:
        """Procesa un trozo de stdout y devuelve los eventos válidos completos."""
        if self.excedido:
            return []
        self.bytes_totales += len(chunk)
        if self.bytes_totales > self.max_total:
            self.excedido = True
            return []

        eventos: list[Evento] = []
        inicio = 0
        while True:
            fin = chunk.find(b"\n", inicio)
            if fin == -1:
                self._acumular(chunk[inicio:])
                break
            self._acumular(chunk[inicio:fin])
            ev = self._cerrar_linea()
            if ev is not None:
                eventos.append(ev)
            inicio = fin + 1
            if self.excedido:
                break
        return eventos

    def cerrar(self) -> list[Evento]:
        """Procesa lo que quede en el buffer al terminar el stream."""
        if self.excedido or (not self._buffer and not self._descartando_linea):
            return []
        ev = self._cerrar_linea()
        return [ev] if ev is not None else []

    def _acumular(self, datos: bytes) -> None:
        if self._descartando_linea:
            return
        if len(self._buffer) + len(datos) > self.max_linea:
            # No guardamos la línea gigante en memoria: la marcamos y la saltamos.
            self._buffer.clear()
            self._descartando_linea = True
            return
        self._buffer.extend(datos)

    def _cerrar_linea(self) -> Evento | None:
        if self._descartando_linea:
            self._descartando_linea = False
            self.descartados += 1
            return None
        linea = bytes(self._buffer).strip()
        self._buffer.clear()
        if not linea:
            return None
        try:
            ev = ADAPTADOR_EVENTO.validate_json(linea)
        except ValidationError:
            self.descartados += 1
            return None
        self._validos += 1
        if self._validos > self.max_eventos:
            self.excedido = True
            return None
        return ev
