"""Costo de la vista previa en vivo: re-codificación aislada de frames y ancho de banda.

    python experiments/exp2_contencion/costo_frames.py   (con el stack arriba: make up)

Analiza unos pocos sitios legítimos con el perfil gvisor y registra, por análisis, cuántos
frames se aceptaron, el tiempo de re-codificación con Pillow en el proceso aislado
(total y por frame), los bytes de imágenes que llegarían al navegador y la duración total.
Ética: sitios legítimos y populares, uno cada 2 s.
Salida: experiments/results/exp2_costo_frames.csv
"""

import csv
import statistics
import time
from pathlib import Path

import docker

from qrsandbox.orquestador.ejecutor import ConfigWorker, ejecutar

SITIOS = ["https://example.com", "https://github.com", "https://es.wikipedia.org/wiki/C%C3%B3digo_QR",
          "https://www.bancoestado.cl", "https://www.emol.com", "https://www.sii.cl"]
REPETICIONES = 2
SALIDA = Path(__file__).resolve().parents[1] / "results" / "exp2_costo_frames.csv"


def main():
    cliente = docker.from_env()
    filas = []
    for _ in range(REPETICIONES):
        for url in SITIOS:
            r = ejecutar(url, ConfigWorker(perfil="gvisor"), cliente)
            m = r.metricas
            filas.append({
                "url": url, "duracion_ms": r.duracion_ms, "frames": r.frames,
                "recodificacion_ms_total": m["recodificacion_ms_total"],
                "recodificacion_ms_por_frame": m["recodificacion_ms_por_frame"],
                "frames_rechazados": m["frames_rechazados"],
                "kb_frames": round(m["bytes_frames"] / 1024, 1),
                "kb_salida_worker": round(m["bytes_salida_worker"] / 1024, 1),
                "error": r.error or "",
            })
            f = filas[-1]
            print(f"{url[:40]:<40} {f['frames']:>3} frames, {f['recodificacion_ms_por_frame']:>5} ms/frame, "
                  f"{f['kb_frames']:>7} KB, {f['duracion_ms']} ms {f['error']}")
            time.sleep(2)
    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    with SALIDA.open("w", newline="") as a:
        w = csv.DictWriter(a, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    ok = [f for f in filas if f["frames"]]
    print(f"\nmediana: {statistics.median(f['frames'] for f in ok)} frames, "
          f"{statistics.median(f['recodificacion_ms_por_frame'] for f in ok)} ms/frame, "
          f"{statistics.median(f['kb_frames'] for f in ok)} KB por análisis; "
          f"re-codificación = {statistics.median(f['recodificacion_ms_total'] / f['duracion_ms'] * 100 for f in ok):.1f} % "
          "de la duración (en paralelo a la navegación)")


if __name__ == "__main__":
    main()
