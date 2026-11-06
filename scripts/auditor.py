"""Auditor del QR Transparency Log.

Uso:
    python scripts/auditor.py [--url http://127.0.0.1:8000] [--estado data/auditor.json]
                              [--completo] [--clave-comercio <base64>] [--entre A B]

- Sin opciones: fija la clave del log (la primera vez), verifica la firma del STH actual
  y que sea una extensión del último STH visto (prueba de consistencia). Guarda el STH.
- --completo: además descarga todas las hojas, recalcula la raíz y verifica las firmas.
- --clave-comercio: lista las entradas registradas con esa clave (monitoreo).
- --entre A B: verifica la consistencia entre los STH firmados de tamaños A y B.
Sale con código 1 si hay alertas.
"""

import argparse
import json
import sys
from pathlib import Path

import httpx

from qrsandbox.tlog.auditor import auditar, verificar_entre


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--estado", type=Path, default=Path("data/auditor.json"))
    p.add_argument("--completo", action="store_true")
    p.add_argument("--clave-comercio")
    p.add_argument("--entre", nargs=2, type=int, metavar=("A", "B"))
    args = p.parse_args()

    estado = json.loads(args.estado.read_text()) if args.estado.exists() else {}
    with httpx.Client(base_url=args.url, timeout=30) as http:
        if args.entre:
            clave = estado.get("clave_log") or http.get("/log/clave-publica").json()["clave_publica"]
            motivo = verificar_entre(http, *args.entre, clave)
            print(f"ALERTA: {motivo}" if motivo else f"OK: {args.entre[0]} -> {args.entre[1]} consistente")
            return 1 if motivo else 0
        informe = auditar(http, estado, args.completo, args.clave_comercio)

    for nota in informe["notas"]:
        print(f"OK: {nota}")
    for alerta in informe["alertas"]:
        print(f"ALERTA: {alerta}")
    if args.clave_comercio:
        print(f"entradas con esa clave: {informe['entradas_de_la_clave']}")
    print(f"STH: tamaño {informe['sth']['tamano']}, raíz {informe['sth']['raiz'][:16]}…")
    if informe["ok"]:
        args.estado.parent.mkdir(parents=True, exist_ok=True)
        args.estado.write_text(json.dumps(estado, indent=2))
    return 0 if informe["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
