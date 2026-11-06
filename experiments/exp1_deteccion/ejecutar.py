"""Experimento 1 (paso 2): compara tres formas de detectar URLs maliciosas.

    python experiments/exp1_deteccion/ejecutar.py [--limite 20] [--perfil gvisor]

Para cada URL de dataset.csv:
  (A) solo listas negras: snapshots ANTERIORES a la fecha del dataset (separación temporal),
      y como cota optimista también la lista del MISMO día ("A_mismo_dia").
  (B) solo heurísticas estáticas (incluye RDAP/whois/TLS y la lista negra de días previos).
  (C) estático + dinámico: además se abre en el sandbox real (worker con el perfil elegido)
      y se combina todo con el motor de veredicto.
El veredicto se calcula aquí (no en la API) para controlar exactamente qué listas se usan.
Se predice "maliciosa" si el estado no es `sin_alertas` (puntaje >= 35).

Ética: URLs de feeds públicos de investigación, como máximo 1 análisis cada 2 s, solo se
cargan las páginas (nunca se envían datos). Reanudable: salta las URLs ya medidas.
Salida: experiments/results/exp1_detalle.csv
"""

import argparse
import csv
import re
import shutil
import tempfile
import time
from pathlib import Path

import docker

from qrsandbox.orquestador.ejecutor import ConfigWorker, ejecutar
from qrsandbox.senales.dominio import partes_host
from qrsandbox.senales.estaticas import analizar_url
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.senales.red import ProveedorRedReal
from qrsandbox.veredicto.motor import evaluar

AQUI = Path(__file__).resolve().parent
SNAPSHOTS = AQUI.parents[1] / "data" / "listas" / "snapshots"
SALIDA = AQUI.parent / "results" / "exp1_detalle.csv"
FECHA = re.compile(r"(\d{4}-\d{2}-\d{2})")
PAUSA_S = 2.0
CAMPOS = ["url", "etiqueta", "fuente", "A", "A_mismo_dia", "B", "C", "puntaje_B", "puntaje_C",
          "estado_C", "razones_C", "ms_B", "ms_C", "error_sandbox", "titulo", "url_final"]


def listas_hasta(fecha: str, incluir_mismo_dia: bool) -> ListasNegras:
    """Índice en memoria solo con snapshots de antes de `fecha` (o hasta ese día)."""
    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "snapshots"
        destino.mkdir()
        for f in SNAPSHOTS.iterdir():
            m = FECHA.search(f.name)
            if not m:
                continue
            if m.group(1) < fecha or (incluir_mismo_dia and m.group(1) == fecha) or f.name.startswith("tranco"):
                shutil.copy(f, destino / f.name)
        return ListasNegras.desde_directorio(tmp)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--limite", type=int, help="solo las primeras N URLs de cada clase (piloto)")
    p.add_argument("--perfil", default="gvisor")
    a = p.parse_args()

    filas = list(csv.DictReader((AQUI / "dataset.csv").open()))
    if a.limite:
        filas = ([f for f in filas if f["etiqueta"] == "maliciosa"][: a.limite]
                 + [f for f in filas if f["etiqueta"] == "benigna"][: a.limite])
    fecha = filas[0]["fecha"]
    previas = listas_hasta(fecha, incluir_mismo_dia=False)
    mismo_dia = listas_hasta(fecha, incluir_mismo_dia=True)
    red = ProveedorRedReal()
    cliente = docker.from_env()
    config = ConfigWorker(perfil=a.perfil)

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    hechas = set()
    if SALIDA.exists():
        hechas = {f["url"] for f in csv.DictReader(SALIDA.open())}
    nuevo = not SALIDA.exists()
    with SALIDA.open("a", newline="") as archivo:
        w = csv.DictWriter(archivo, fieldnames=CAMPOS)
        if nuevo:
            w.writeheader()
        for i, f in enumerate(filas, 1):
            url = f["url"]
            if url in hechas:
                continue
            t0 = time.perf_counter()
            estatico = analizar_url(url, listas=previas, red=red)
            v_b = evaluar(estatico, listas=previas)
            ms_b = (time.perf_counter() - t0) * 1000

            t1 = time.perf_counter()
            r = ejecutar(url, config, cliente)
            final = r.resultado.url_final if r.resultado else None
            estatico_final = None
            if final and partes_host(final).host != estatico.partes.host:
                estatico_final = analizar_url(final, listas=previas, red=red)
            v_c = evaluar(estatico, estatico_final, r, listas=previas)
            ms_c = ms_b + (time.perf_counter() - t1) * 1000

            fila = {
                "url": url, "etiqueta": f["etiqueta"], "fuente": f["fuente"],
                "A": int(previas.consultar(url) is not None),
                "A_mismo_dia": int(mismo_dia.consultar(url) is not None),
                "B": int(v_b["estado"] != "sin_alertas"), "C": int(v_c["estado"] != "sin_alertas"),
                "puntaje_B": v_b["puntaje"], "puntaje_C": v_c["puntaje"], "estado_C": v_c["estado"],
                "razones_C": ";".join(x["codigo"] for x in v_c["razones"]),
                "ms_B": round(ms_b), "ms_C": round(ms_c), "error_sandbox": r.error or "",
                "titulo": (r.resultado.titulo if r.resultado else "")[:80], "url_final": final or "",
            }
            w.writerow(fila)
            archivo.flush()
            print(f"[{i}/{len(filas)}] {f['etiqueta']:>9} A={fila['A']} B={fila['B']} C={fila['C']} "
                  f"({fila['puntaje_C']:>3}) {url[:70]}")
            time.sleep(PAUSA_S)  # ética: máximo 1 análisis cada 2 s


if __name__ == "__main__":
    main()
