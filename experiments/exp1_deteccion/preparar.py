"""Experimento 1 (paso 1): arma el conjunto de URLs con etiqueta y SEPARACIÓN TEMPORAL.

    python experiments/exp1_deteccion/preparar.py [--fecha 2026-11-14] [--n 300] [--semilla 7]

- Maliciosas: URLs de OpenPhish que aparecen por PRIMERA vez en el snapshot de `--fecha`
  (no estaban en ningún snapshot anterior). Así la lista negra de los días previos, que usa
  el método (A), no las contiene por construcción: se mide de verdad si las listas
  "llegan tarde".
- Benignas: sitios chilenos comunes (chilenos.txt) + sitios legítimos en hosting gratuito
  (benignas_hosting_prueba.txt: páginas oficiales de repos populares de GitHub en github.io,
  vercel.app, netlify.app, pages.dev; es la mitad de PRUEBA, que no se miró al diseñar la señal
  de hosting gratuito) + el resto, una muestra de los dominios 10.001–110.000 de Tranco (no los
  más famosos, que serían demasiado fáciles; nota: el filtro de popularidad usa el top 100.000).
  Sin los sitios en hosting gratuito, la tasa de falsos positivos de esa señal no se mediría.

Salida: experiments/exp1_deteccion/dataset.csv (url, etiqueta, fuente, fecha).
"""

import argparse
import csv
import random
import re
from pathlib import Path

AQUI = Path(__file__).resolve().parent
SNAPSHOTS = AQUI.parents[1] / "data" / "listas" / "snapshots"
FECHA = re.compile(r"(\d{4}-\d{2}-\d{2})")


def urls_openphish_por_fecha() -> dict[str, set[str]]:
    por_fecha: dict[str, set[str]] = {}
    for f in sorted(SNAPSHOTS.glob("urls-openphish-*.txt")):
        fecha = FECHA.search(f.name).group(1)
        por_fecha[fecha] = {ln.strip() for ln in f.read_text().splitlines()
                            if ln.startswith(("http://", "https://"))}
    return por_fecha


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--fecha", help="snapshot de las maliciosas (por defecto, el más reciente)")
    p.add_argument("--n", type=int, default=300, help="URLs por clase")
    p.add_argument("--semilla", type=int, default=7)
    a = p.parse_args()
    rng = random.Random(a.semilla)

    por_fecha = urls_openphish_por_fecha()
    if not por_fecha:
        raise SystemExit("No hay snapshots de OpenPhish: corre `make listas`.")
    fecha = a.fecha or max(por_fecha)
    anteriores = set().union(*(u for f, u in por_fecha.items() if f < fecha))
    nuevas = sorted(por_fecha[fecha] - anteriores)
    if not anteriores:
        print(f"AVISO: no hay snapshots anteriores a {fecha}: el método (A) no tendrá lista "
              "previa. Junta snapshots de varios días (make listas a diario) para un resultado válido.")
    maliciosas = rng.sample(nuevas, min(a.n, len(nuevas)))
    print(f"maliciosas: {len(maliciosas)} de {len(nuevas)} nuevas el {fecha} "
          f"({len(anteriores)} URLs en snapshots anteriores)")

    chilenos = [ln.strip() for ln in (AQUI / "chilenos.txt").read_text().splitlines()
                if ln.startswith("https://")]
    tranco = sorted(SNAPSHOTS.glob("tranco-*.csv"))
    if not tranco:
        raise SystemExit("Falta el snapshot de Tranco: corre `make listas`.")
    candidatos = []
    for linea in tranco[-1].read_text().splitlines():
        rango, _, dominio = linea.partition(",")
        if rango.isdigit() and 10_000 < int(rango) <= 110_000:
            candidatos.append(dominio.strip())
    hosting = [ln.strip() for ln in (AQUI / "benignas_hosting_prueba.txt").read_text().splitlines()
               if ln.startswith("https://")]
    n_tranco = max(0, len(maliciosas) - len(chilenos) - len(hosting))
    benignas = chilenos + hosting + [f"https://{d}/" for d in rng.sample(candidatos, n_tranco)]
    print(f"benignas: {len(chilenos)} chilenas + {len(hosting)} en hosting gratuito + "
          f"{n_tranco} de Tranco (rangos 10.001–110.000)")

    with (AQUI / "dataset.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "etiqueta", "fuente", "fecha"])
        for u in maliciosas:
            w.writerow([u, "maliciosa", "openphish", fecha])
        for u in benignas:
            fuente = "chilenos" if u in chilenos else "hosting" if u in hosting else "tranco"
            w.writerow([u, "benigna", fuente, fecha])
    print(f"-> {AQUI / 'dataset.csv'}")


if __name__ == "__main__":
    main()
