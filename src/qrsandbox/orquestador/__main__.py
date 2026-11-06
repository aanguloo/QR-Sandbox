"""CLI del orquestador: analiza una URL desde la terminal.

    python -m qrsandbox.orquestador https://example.com [--captura salida.jpg]
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from qrsandbox.comun.esquemas import SolicitudAnalisis
from qrsandbox.orquestador.ejecutor import ejecutar


def main() -> int:
    parser = argparse.ArgumentParser(description="Analiza una URL en un worker efímero")
    parser.add_argument("url")
    parser.add_argument("--captura", type=Path, help="guarda la captura JPEG en este archivo")
    args = parser.parse_args()
    try:
        solicitud = SolicitudAnalisis(url=args.url)
    except ValidationError as e:
        print(f"URL inválida: {e.errors()[0]['msg']}", file=sys.stderr)
        return 2

    r = ejecutar(solicitud.url)
    if args.captura and r.captura_jpeg_b64:
        args.captura.parent.mkdir(parents=True, exist_ok=True)
        args.captura.write_bytes(base64.b64decode(r.captura_jpeg_b64))
    salida = r.model_dump(mode="json")
    salida["captura_jpeg_b64"] = f"<{len(r.captura_jpeg_b64 or '')} chars>"
    print(json.dumps(salida, ensure_ascii=False, indent=2))
    return 0 if r.error is None else 1


if __name__ == "__main__":
    sys.exit(main())
