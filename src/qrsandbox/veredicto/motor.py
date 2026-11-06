"""Motor de veredicto: combina señales en un puntaje, un estado y una explicación.

Es deliberadamente simple y auditable: suma de pesos de una tabla fija
(`senales/hallazgos.py`), sin aprendizaje automático. Cada punto del puntaje se puede
rastrear a una razón escrita en lenguaje simple.
"""

from qrsandbox.comun.esquemas import ResultadoAnalisis
from qrsandbox.senales.dinamicas import senales_dinamicas
from qrsandbox.senales.dominio import Marca, cargar_marcas
from qrsandbox.senales.estaticas import ResultadoEstatico
from qrsandbox.senales.hallazgos import Hallazgo
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.tlog.log import leer_hoja

UMBRAL_PELIGROSO = 70
UMBRAL_SOSPECHOSO = 35
MAX_FRASES_RESUMEN = 4


def unir_es(frases: list[str]) -> str:
    if len(frases) <= 1:
        return "".join(frases)
    return ", ".join(frases[:-1]) + " y " + frases[-1]


def _destino(entrada: dict) -> str | None:
    try:
        return leer_hoja(entrada["hoja"])[0].url_destino
    except (ValueError, KeyError, TypeError):
        return None


def senales_log(consulta: dict | None) -> list[Hallazgo]:
    if not consulta:
        return []
    if consulta["estado"] == "no_coincide":
        destinos = [d for e in consulta["otros_destinos_cercanos"][:2] if (d := _destino(e))]
        lista = ", ".join(destinos) or "otro sitio"
        return [Hallazgo("log_no_coincide", "En esta ubicación hay un QR registrado por el "
                         f"comercio que apunta a {lista}, no a esta dirección: puede ser un "
                         "sticker pegado encima del QR original.",
                         "en este lugar el QR registrado apunta a otro sitio (posible sticker "
                         "encima del original)")]
    if consulta["estado"] == "verificado":
        return [Hallazgo("log_verificado", "Este QR está registrado y firmado por el comercio "
                         "para esta ubicación (con prueba de inclusión en el log).",
                         "está registrado por el comercio en esta ubicación")]
    return []


def evaluar(
    estatico: ResultadoEstatico,
    estatico_final: ResultadoEstatico | None = None,
    analisis: ResultadoAnalisis | None = None,
    consulta_log: dict | None = None,
    marcas: tuple[Marca, ...] | None = None,
    listas: ListasNegras | None = None,
) -> dict:
    marcas = marcas if marcas is not None else cargar_marcas()
    todos = (
        senales_log(consulta_log)
        + estatico.hallazgos
        + (estatico_final.hallazgos if estatico_final else [])
        + senales_dinamicas(analisis, marcas, listas.es_popular if listas else None)
    )
    # Un mismo tipo de hallazgo cuenta una sola vez (p. ej. TLD riesgoso al inicio y al final).
    unicos: dict[str, Hallazgo] = {}
    for h in todos:
        unicos.setdefault(h.codigo, h)
    hallazgos = sorted(unicos.values(), key=lambda h: h.peso, reverse=True)

    puntaje = max(0, min(100, sum(h.peso for h in hallazgos)))
    if puntaje >= UMBRAL_PELIGROSO:
        estado = "peligroso"
    elif puntaje >= UMBRAL_SOSPECHOSO:
        estado = "sospechoso"
    else:
        estado = "sin_alertas"

    destino = (estatico_final or estatico).partes.host  # ASCII/punycode: no engaña a la vista
    frases = [h.frase for h in hallazgos if h.peso > 0][:MAX_FRASES_RESUMEN]
    if frases:
        resumen = f"Vas a {destino}: {unir_es(frases)}."
    else:
        resumen = (f"Vas a {destino}: no encontramos señales de riesgo. Esto no garantiza que "
                   "sea seguro; revisa que sea el sitio que esperas.")
    if "log_verificado" in unicos:
        resumen += " Este QR está registrado por el comercio en esta ubicación."
    if analisis is None or analisis.resultado is None:
        resumen += " (No se pudo cargar la página en el sandbox: solo se usaron señales estáticas.)"

    return {
        "puntaje": puntaje,
        "estado": estado,
        "resumen": resumen,
        "razones": [h.a_dict() for h in hallazgos],
        "destino": destino,
    }
