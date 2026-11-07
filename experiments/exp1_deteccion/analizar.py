"""Experimento 1 (paso 3): métricas, falsos negativos y gráficos.

    python experiments/exp1_deteccion/analizar.py

Lee experiments/results/exp1_detalle.csv y escribe exp1_metricas.csv,
exp1_falsos_negativos.csv, exp1_falsos_positivos.csv y figures/exp1_*.png.
"""

import csv
import statistics
from collections import Counter
from pathlib import Path

RESULTADOS = Path(__file__).resolve().parents[1] / "results"
FIGURAS = RESULTADOS.parent / "figures"
METODOS = {"A": "(A) solo listas negras", "A_mismo_dia": "(A*) lista del mismo día (optimista)",
           "B": "(B) heurísticas estáticas", "C": "(C) estático + dinámico"}


def p(valores, q):
    v = sorted(valores)
    return v[min(len(v) - 1, int(q * len(v)))] if v else 0


def main():
    filas = list(csv.DictReader((RESULTADOS / "exp1_detalle.csv").open()))
    metricas = []
    for m, nombre in METODOS.items():
        tp = sum(1 for f in filas if f["etiqueta"] == "maliciosa" and f[m] == "1")
        fn = sum(1 for f in filas if f["etiqueta"] == "maliciosa" and f[m] == "0")
        fp = sum(1 for f in filas if f["etiqueta"] == "benigna" and f[m] == "1")
        tn = sum(1 for f in filas if f["etiqueta"] == "benigna" and f[m] == "0")
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        ms = [float(f["ms_C"] if m == "C" else f["ms_B"]) for f in filas] if m in ("B", "C") else [0]
        metricas.append({"metodo": nombre, "vp": tp, "fn": fn, "fp": fp, "vn": tn,
                         "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
                         "tasa_fp": round(fp / (fp + tn), 3) if fp + tn else 0,
                         "latencia_ms_p50": round(statistics.median(ms)), "latencia_ms_p95": round(p(ms, 0.95))})
    with (RESULTADOS / "exp1_metricas.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(metricas[0]))
        w.writeheader()
        w.writerows(metricas)
    for m in metricas:
        print(f"{m['metodo']:<40} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} "
              f"FP={m['tasa_fp']:.2f} p50={m['latencia_ms_p50']} ms p95={m['latencia_ms_p95']} ms")

    # Falsos positivos por fuente de benignas (p. ej. la señal de hosting gratuito solo puede
    # equivocarse en "hosting").
    por_fuente = []
    for fuente in sorted({f["fuente"] for f in filas if f["etiqueta"] == "benigna"}):
        grupo = [f for f in filas if f["etiqueta"] == "benigna" and f["fuente"] == fuente]
        fila = {"fuente": fuente, "n": len(grupo)}
        for m in ("A", "B", "C"):
            fila[f"tasa_fp_{m}"] = round(sum(f[m] == "1" for f in grupo) / len(grupo), 3)
        por_fuente.append(fila)
        print(f"benignas {fuente:<9} n={fila['n']:<4} FP: A={fila['tasa_fp_A']} B={fila['tasa_fp_B']} C={fila['tasa_fp_C']}")
    with (RESULTADOS / "exp1_fp_por_fuente.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(por_fuente[0]))
        w.writeheader()
        w.writerows(por_fuente)

    # Análisis cualitativo: qué tenían (y qué no) las maliciosas que se escaparon.
    fns = [f for f in filas if f["etiqueta"] == "maliciosa" and f["C"] == "0"]
    fps = [f for f in filas if f["etiqueta"] == "benigna" and f["C"] == "1"]
    for nombre, lista in (("exp1_falsos_negativos.csv", fns), ("exp1_falsos_positivos.csv", fps)):
        with (RESULTADOS / nombre).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["url", "puntaje_C", "razones_C", "error_sandbox", "titulo", "url_final"])
            w.writeheader()
            w.writerows({k: x[k] for k in w.fieldnames} for x in lista)
    errores = Counter("sandbox con error" if f["error_sandbox"] else "cargó" for f in fns)
    print(f"falsos negativos de (C): {len(fns)} ({dict(errores)}); falsos positivos: {len(fps)}")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    FIGURAS.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 4))
    ancho = 0.2
    for i, clave in enumerate(["precision", "recall", "f1", "tasa_fp"]):
        ax.bar([x + i * ancho for x in range(len(metricas))], [m[clave] for m in metricas], ancho, label=clave)
    ax.set_xticks([x + 1.5 * ancho for x in range(len(metricas))], [m["metodo"] for m in metricas], fontsize=7)
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8)
    ax.set_title(f"Detección ({sum(f['etiqueta'] == 'maliciosa' for f in filas)} maliciosas, "
                 f"{sum(f['etiqueta'] == 'benigna' for f in filas)} benignas)")
    fig.tight_layout()
    fig.savefig(FIGURAS / "exp1_metricas.png", dpi=150)

    fig, ax = plt.subplots(figsize=(6, 3.5))
    for etiqueta, color in (("maliciosa", "#b42318"), ("benigna", "#1d6b3a")):
        ax.hist([int(f["puntaje_C"]) for f in filas if f["etiqueta"] == etiqueta], bins=range(0, 105, 5),
                alpha=0.6, label=etiqueta, color=color)
    ax.axvline(35, color="k", linestyle="--", linewidth=1)
    ax.text(36, ax.get_ylim()[1] * 0.9, "umbral 35", fontsize=8)
    ax.set_xlabel("Puntaje del veredicto (C)")
    ax.set_ylabel("URLs")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURAS / "exp1_puntajes.png", dpi=150)


if __name__ == "__main__":
    main()
