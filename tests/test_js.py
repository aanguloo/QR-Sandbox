"""Fase 5: el JS de verificación del navegador coincide con Python (corre con Node)."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qrsandbox.tlog import merkle
from qrsandbox.tlog.log import LogTransparencia
from qrsandbox.tlog.registro import Registro, SolicitudRegistro, bytes_canonicos, firmar_registro

from .test_merkle import HASHES_CT, HOJAS_CT

RAIZ = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="requiere Node.js")


def _vectores(tmp_path) -> dict:
    hojas = [merkle.hash_hoja(f"h{i}".encode()) for i in range(20)]
    falsa = merkle.hash_hoja(b"falsa").hex()
    inclusion, consistencia = [], []
    for n in range(1, 21):
        r = merkle.raiz(hojas[:n])
        for i in range(n):
            inclusion.append({"indice": i, "tamano": n, "hoja": hojas[i].hex(), "otra": falsa,
                              "ruta": [h.hex() for h in merkle.ruta_inclusion(i, hojas[:n])],
                              "raiz": r.hex()})
        for m in range(1, n):
            consistencia.append({"m": m, "n": n, "raiz_m": merkle.raiz(hojas[:m]).hex(),
                                 "raiz_n": r.hex(), "otra": falsa,
                                 "ruta": [h.hex() for h in merkle.prueba_consistencia(m, hojas[:n])]})
    clave = Ed25519PrivateKey.generate()
    s = firmar_registro(clave, url_destino="https://xn--caf-dma.ejemplo.cl/%C3%B1and%C3%BA?x=1",
                        lat_e6=-33437800, lon_e6=-70650500, radio_m=30,
                        descripcion='Café "La Ñandú" ☕ — mesa 4 / <script>', timestamp=int(time.time()))
    log = LogTransparencia(tmp_path / "t.sqlite", Ed25519PrivateKey.generate())
    recibo = log.agregar(s)
    objetos = [s.registro.model_dump(), {"b": [1, {"z": "é", "a": None}], "a": True, "ñ": " \t\""}]
    return {
        "canonicos": [{"objeto": o, "texto": bytes_canonicos(o).decode()} for o in objetos],
        "hojas": [{"datos": d.hex(), "hash": h.hex()} for d, h in zip(HOJAS_CT, HASHES_CT, strict=True)],
        "inclusion": inclusion,
        "consistencia": consistencia,
        "registro_python": s.model_dump(),
        "recibo": recibo,
    }


def test_cripto_js_contra_python(tmp_path):
    vectores, salida = tmp_path / "vectores.json", tmp_path / "salida.json"
    vectores.write_text(json.dumps(_vectores(tmp_path), ensure_ascii=False))
    r = subprocess.run(
        [shutil.which("node"), "--test", "tests/js/cripto.test.mjs"], check=False, cwd=RAIZ,
        capture_output=True, text=True,
        env={"VECTORES": str(vectores), "SALIDA": str(salida)},
        timeout=120,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    # Lo que firmó el navegador lo acepta el log de Python.
    d = json.loads(salida.read_text())
    # Ed25519 es determinista: la clave recuperada del respaldo firma exactamente igual.
    assert d["firma"] == d["firma2"]
    s = SolicitudRegistro(registro=Registro.model_validate(d["registro"]), firma=d["firma"])
    assert LogTransparencia(tmp_path / "js.sqlite", Ed25519PrivateKey.generate()).agregar(s)
