"""Filtro anti-DoS de eventos ya validados (sigue siendo salida de un worker hostil).

Aunque cada evento pase el esquema, un worker comprometido (o una página que hace miles
de requests) podría inundar el canal en vivo. El filtro aplica, con el reloj del
ORQUESTADOR (el `t_ms` del worker no es confiable):
- tasa máxima (token bucket) de eventos por segundo;
- tope por tipo de evento: lo que exceda se AGRUPA en un contador, para mostrar
  "+230 requests a dominios de terceros" en vez de 230 líneas;
- intervalo mínimo entre frames del screencast.
El evento `fin` nunca se descarta por tasa: sin él no hay resultado.
"""

import time
from collections import Counter
from dataclasses import dataclass, field

LIMITES_POR_TIPO = {
    "redireccion": 30,
    "navegacion": 30,
    "request_tercero": 25,
    "formulario_password": 5,
    "descarga_bloqueada": 10,
    "marca_detectada": 20,
    "permiso_solicitado": 4,
    "captura": 120,
    "error": 10,
    "fin": 1,
}


@dataclass
class FiltroEventos:
    tasa_por_s: float = 50.0
    rafaga: float = 100.0
    intervalo_captura_s: float = 0.25
    reloj: callable = time.monotonic
    descartados_tasa: int = 0
    agrupados: Counter = field(default_factory=Counter)
    _conteo: Counter = field(default_factory=Counter)
    _fichas: float | None = None
    _ultimo: float | None = None
    _ultima_captura: float = float("-inf")

    def admitir(self, tipo: str) -> bool:
        ahora = self.reloj()
        if tipo != "fin" and not self._gastar_ficha(ahora):
            self.descartados_tasa += 1
            return False
        if tipo == "captura":
            if ahora - self._ultima_captura < self.intervalo_captura_s:
                self.descartados_tasa += 1
                return False
            self._ultima_captura = ahora
        if self._conteo[tipo] >= LIMITES_POR_TIPO.get(tipo, 0):
            self.agrupados[tipo] += 1
            return False
        self._conteo[tipo] += 1
        return True

    def _gastar_ficha(self, ahora: float) -> bool:
        if self._fichas is None:
            self._fichas, self._ultimo = self.rafaga, ahora
        self._fichas = min(self.rafaga, self._fichas + (ahora - self._ultimo) * self.tasa_por_s)
        self._ultimo = ahora
        if self._fichas < 1:
            return False
        self._fichas -= 1
        return True
