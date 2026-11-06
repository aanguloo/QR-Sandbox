"""Descarga snapshots CON FECHA de listas públicas y construye el índice offline.

    python scripts/descargar_listas.py [--dir data/listas] [--sin-tranco]

Fuentes (públicas, sin API key; verificadas el 6-nov-2026):
- OpenPhish (feed comunitario): ~300 URLs de phishing activas.
- Phishing.Database (github.com/Phishing-Database): enlaces nuevos del día y dominios
  activos (~500 mil). Es un agregador de muchas fuentes: más cobertura, pero más ruido
  (puede incluir algún dominio legítimo); por eso la coincidencia por dominio pesa menos y
  no aplica a sitios populares.
- Tranco (tranco-list.eu): top 1M de sitios populares, para no confundir sitios legítimos
  muy visitados con imitaciones de marca.
No incluidas: URLhaus (descargas masivas "410 Gone", ahora exige Auth-Key) y PhishTank
(exige registro). Cualquier otro snapshot se puede dejar a mano en
data/listas/snapshots/urls-<fuente>-<AAAA-MM-DD>.txt.

Correrlo una vez al día ACUMULA snapshots de URLs (sirve para juntar el dataset del
Experimento 1 y para separar por fecha). Las URLs se guardan como texto: nunca se visitan aquí.
"""

import argparse
import io
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

from qrsandbox.senales.listas import construir_indice

PD = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master"
FUENTES = {
    "urls-openphish": "https://openphish.com/feed.txt",
    "urls-phishingdb_nuevas": f"{PD}/phishing-links-NEW-today.txt",
    "dominios-phishingdb": f"{PD}/phishing-domains-ACTIVE.txt",
}
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def main() -> int:
    p = argparse.ArgumentParser(description="Descarga snapshots de listas públicas")
    p.add_argument("--dir", type=Path, default=Path("data/listas"))
    p.add_argument("--sin-tranco", action="store_true", help="no bajar Tranco (10 MB)")
    p.add_argument("--si-falta-hoy", action="store_true",
                   help="no hacer nada si ya existe el snapshot de hoy (para la tarea programada)")
    args = p.parse_args()
    snapshots = args.dir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    hoy = datetime.now(UTC).strftime("%Y-%m-%d")  # fechas en UTC, siempre
    if args.si_falta_hoy and (snapshots / f"urls-openphish-{hoy}.txt").exists():
        print(f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC: ya existe el snapshot de {hoy}, nada que hacer")
        return 0
    errores = 0
    with httpx.Client(timeout=120, follow_redirects=True,
                      headers={"User-Agent": "QR-Sandbox (proyecto academico)"}) as http:
        for nombre, url in FUENTES.items():
            try:
                r = http.get(url)
                r.raise_for_status()
            except httpx.HTTPError as e:
                print(f"{nombre}: ERROR {e}", file=sys.stderr)
                errores += 1
                continue
            lineas = [ln.strip() for ln in r.text.splitlines()
                      if ln.strip() and not ln.startswith("#")]
            if nombre.startswith("urls-"):
                lineas = [ln for ln in lineas if ln.startswith(("http://", "https://"))]
            destino = snapshots / f"{nombre}-{hoy}.txt"
            destino.write_text(f"# fuente: {url}\n# fecha: {hoy}\n" + "\n".join(lineas) + "\n")
            print(f"{nombre}: {len(lineas)} entradas -> {destino}")
        if not args.sin_tranco:
            try:
                r = http.get(TRANCO)
                r.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    csv = z.read(z.namelist()[0]).decode()
                (snapshots / f"tranco-{hoy}.csv").write_text(csv)
                print(f"tranco: {csv.count(chr(10))} dominios")
            except (httpx.HTTPError, zipfile.BadZipFile, IndexError) as e:
                print(f"tranco: ERROR {e}", file=sys.stderr)
                errores += 1

    resumen = construir_indice(args.dir, args.dir / "listas.sqlite")
    print("índice:", ", ".join(f"{k}={v}" for k, v in resumen.items()))
    return 1 if errores == len(FUENTES) + 1 else 0


if __name__ == "__main__":
    sys.exit(main())
