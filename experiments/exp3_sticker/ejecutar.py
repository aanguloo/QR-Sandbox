"""Experimento 3: detección de stickers superpuestos con el QR Transparency Log.

    python experiments/exp3_sticker/ejecutar.py [--qrs 40] [--escaneos 10] [--semilla 7]

Simula, con el log REAL (LogTransparencia + SQLite, en un directorio temporal):
1. Un conjunto de comercios registra QRs firmados en ubicaciones de Santiago centro.
2. Escaneos en tres escenarios:
   - legitimo: alguien escanea el QR real, desde cerca, con error de GPS;
   - sticker:  en el mismo lugar hay un QR pegado encima que lleva a otro sitio;
   - sin_registro: QRs en lugares donde ningún comercio registró nada.
3. Se varía el radio declarado al registrar (10–100 m) y el error del GPS (σ 5–80 m).
   La ubicación además se redondea a 3 decimales (~110 m) por privacidad, igual que en la app.

Mide: tasa de detección de "no coincide" en stickers, tasa de verificación de QRs
legítimos (los que fallan son falsos positivos por imprecisión del GPS), aciertos en
"sin registro", y latencia de la consulta y de la verificación de la prueba de inclusión
según el tamaño del log.

Salidas: experiments/results/exp3_deteccion.csv, exp3_latencia.csv y
experiments/figures/exp3_*.png. Reproducible con --semilla.
"""

import argparse
import csv
import math
import random
import statistics
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qrsandbox.tlog import merkle
from qrsandbox.tlog.log import LogTransparencia
from qrsandbox.tlog.registro import firmar_registro

RAIZ = Path(__file__).resolve().parents[1]
RESULTADOS = RAIZ / "results"
FIGURAS = RAIZ / "figures"
# Santiago centro: ~4 x 4 km alrededor de la Plaza de Armas.
LAT0, LON0, LADO_M = -33.4378, -70.6505, 4000
RADIOS = [10, 30, 50, 100]
ERRORES_GPS = [5, 10, 20, 40, 80]
M_POR_GRADO = 111_320


def desplazar(lat, lon, dx_m, dy_m):
    return (lat + dy_m / M_POR_GRADO, lon + dx_m / (M_POR_GRADO * math.cos(math.radians(lat))))


def con_error_gps(rng, lat, lon, sigma):
    return desplazar(lat, lon, rng.gauss(0, sigma), rng.gauss(0, sigma))


ESCENARIOS = {"disperso": 4000, "denso": 300}  # lado del área en metros


def lugares(rng, n, separacion_min=0, lado_m=LADO_M):
    """n ubicaciones al azar en un cuadrado de `lado_m` (opcionalmente separadas entre sí)."""
    salida = []
    while len(salida) < n:
        lat, lon = desplazar(LAT0, LON0, rng.uniform(-lado_m / 2, lado_m / 2),
                             rng.uniform(-lado_m / 2, lado_m / 2))
        if all(math.dist((lat * M_POR_GRADO, lon * M_POR_GRADO * 0.83),
                         (a * M_POR_GRADO, b * M_POR_GRADO * 0.83)) >= separacion_min
               for a, b in salida):
            salida.append((lat, lon))
    return salida


def registrar(log, rng, qrs, radio):
    ahora = int(time.time())
    for i, (lat, lon) in enumerate(qrs):
        log.agregar(firmar_registro(
            Ed25519PrivateKey.generate(), url_destino=f"https://pagos.comercio{i}.cl/mesa/{i % 9}",
            lat_e6=round(lat * 1e6), lon_e6=round(lon * 1e6), radio_m=radio,
            descripcion=f"QR simulado {i}", timestamp=ahora))


def experimento_deteccion(qrs_n, escaneos, semilla, escenario="disperso"):
    """`denso`: 40 comercios en 300 x 300 m (patio de comidas, feria): un QR legítimo puede
    quedar cerca del QR de OTRO comercio y dar una falsa alerta de "no coincide"."""
    filas = []
    rng = random.Random(semilla)
    qrs = lugares(rng, qrs_n, lado_m=ESCENARIOS[escenario])
    libres = []  # lugares lejos (>1 km) de cualquier QR registrado, para "sin registro"
    while len(libres) < qrs_n:
        lat, lon = desplazar(LAT0, LON0, rng.uniform(-6000, 6000), rng.uniform(-6000, 6000))
        if all(math.dist((lat, lon), q) * M_POR_GRADO > 1000 for q in qrs):
            libres.append((lat, lon))
    for radio in RADIOS:
        with tempfile.TemporaryDirectory() as tmp:
            log = LogTransparencia(Path(tmp) / "log.sqlite", Ed25519PrivateKey.generate())
            registrar(log, rng, qrs, radio)
            for sigma in ERRORES_GPS:
                conteo = {"legitimo": {}, "sticker": {}, "sin_registro": {}}
                for i, (lat, lon) in enumerate(qrs):
                    url = f"https://pagos.comercio{i}.cl/mesa/{i % 9}"
                    for _ in range(escaneos):
                        e = log.consultar(url, *con_error_gps(rng, lat, lon, sigma))["estado"]
                        conteo["legitimo"][e] = conteo["legitimo"].get(e, 0) + 1
                        e = log.consultar(f"https://pago-rapido-{i}.xyz/m", *con_error_gps(rng, lat, lon, sigma))["estado"]
                        conteo["sticker"][e] = conteo["sticker"].get(e, 0) + 1
                for lat, lon in libres:
                    for _ in range(escaneos):
                        e = log.consultar("https://otro.cl/", *con_error_gps(rng, lat, lon, sigma))["estado"]
                        conteo["sin_registro"][e] = conteo["sin_registro"].get(e, 0) + 1
                total = qrs_n * escaneos
                filas.append({
                    "escenario": escenario,
                    "radio_m": radio, "error_gps_m": sigma, "qrs": qrs_n, "escaneos_por_escenario": total,
                    "sticker_detectado": conteo["sticker"].get("no_coincide", 0) / total,
                    "sticker_sin_registro": conteo["sticker"].get("sin_registro", 0) / total,
                    "legitimo_verificado": conteo["legitimo"].get("verificado", 0) / total,
                    "legitimo_no_coincide": conteo["legitimo"].get("no_coincide", 0) / total,
                    "legitimo_sin_registro": conteo["legitimo"].get("sin_registro", 0) / total,
                    "sin_registro_correcto": conteo["sin_registro"].get("sin_registro", 0) / total,
                })
                print(f"{escenario:>8} radio {radio:>3} m, GPS σ {sigma:>2} m: sticker detectado "
                      f"{filas[-1]['sticker_detectado']:.0%}, legítimo verificado "
                      f"{filas[-1]['legitimo_verificado']:.0%}, falsa alerta "
                      f"{filas[-1]['legitimo_no_coincide']:.0%}")
    return filas


def experimento_latencia(semilla, tamanos=(10, 100, 500, 1000, 2000), repeticiones=30):
    """Latencia de consultar (servidor) y de verificar la prueba (cliente) según el tamaño."""
    rng = random.Random(semilla)
    filas = []
    with tempfile.TemporaryDirectory() as tmp:
        log = LogTransparencia(Path(tmp) / "log.sqlite", Ed25519PrivateKey.generate())
        qrs = lugares(rng, max(tamanos))
        ahora = int(time.time())
        registrados = 0
        for objetivo in tamanos:
            t_registro = []
            while registrados < objetivo:
                lat, lon = qrs[registrados]
                t0 = time.perf_counter()
                log.agregar(firmar_registro(
                    Ed25519PrivateKey.generate(), url_destino=f"https://c{registrados}.cl/",
                    lat_e6=round(lat * 1e6), lon_e6=round(lon * 1e6), radio_m=30,
                    descripcion="x", timestamp=ahora))
                t_registro.append((time.perf_counter() - t0) * 1000)
                registrados += 1
            t_consulta, t_verificar, largo_prueba = [], [], []
            for _ in range(repeticiones):
                i = rng.randrange(objetivo)
                t0 = time.perf_counter()
                c = log.consultar(f"https://c{i}.cl/", *qrs[i])
                t_consulta.append((time.perf_counter() - t0) * 1000)
                m = c["coincidencias"][0]
                ruta = [bytes.fromhex(h) for h in m["prueba_inclusion"]]
                t0 = time.perf_counter()
                ok = merkle.verificar_inclusion(m["indice"], c["sth"]["tamano"],
                                                merkle.hash_hoja(m["hoja"].encode()), ruta,
                                                bytes.fromhex(c["sth"]["raiz"]))
                t_verificar.append((time.perf_counter() - t0) * 1000)
                assert ok
                largo_prueba.append(len(ruta))
            filas.append({
                "tamano_log": objetivo,
                "registro_ms_p50": statistics.median(t_registro[-50:]),
                "consulta_ms_p50": statistics.median(t_consulta),
                "consulta_ms_p95": sorted(t_consulta)[int(0.95 * len(t_consulta)) - 1],
                "verificacion_ms_p50": statistics.median(t_verificar),
                "hashes_en_prueba": statistics.median(largo_prueba),
                "bytes_prueba": statistics.median(largo_prueba) * 32,
            })
            print(f"log de {objetivo:>5}: consulta p50 {filas[-1]['consulta_ms_p50']:.1f} ms, "
                  f"verificación {filas[-1]['verificacion_ms_p50']:.3f} ms, "
                  f"prueba de {filas[-1]['hashes_en_prueba']:.0f} hashes")
    return filas


def guardar(nombre, filas):
    RESULTADOS.mkdir(parents=True, exist_ok=True)
    with (RESULTADOS / nombre).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)


def graficos(deteccion, latencia):
    import matplotlib
    import matplotlib.ticker

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    FIGURAS.mkdir(parents=True, exist_ok=True)
    fig, ejes = plt.subplots(2, 3, figsize=(13, 7.5), sharey=True)
    titulos = [("sticker_detectado", "Stickers detectados («no coincide»)"),
               ("legitimo_verificado", "QR legítimos verificados"),
               ("legitimo_no_coincide", "Falsas alertas en QR legítimos")]
    for fila, escenario in enumerate(ESCENARIOS):
        for radio in RADIOS:
            filas = [f for f in deteccion if f["radio_m"] == radio and f["escenario"] == escenario]
            if not filas:
                continue
            x = [f["error_gps_m"] for f in filas]
            for col, (clave, titulo) in enumerate(titulos):
                ejes[fila][col].plot(x, [f[clave] * 100 for f in filas], marker="o", label=f"radio {radio} m")
                ejes[fila][col].set_title(f"{titulo}\nescenario {escenario}", fontsize=10)
    for ax in ejes.flat:
        ax.set_xlabel("Error del GPS, σ (m)")
        ax.set_xscale("log")
        ax.set_xticks(ERRORES_GPS, [str(e) for e in ERRORES_GPS])
        ax.xaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
        ax.grid(alpha=0.3)
    for fila in ejes:
        fila[0].set_ylabel("% de escaneos")
    ejes[0][1].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIGURAS / "exp3_deteccion.png", dpi=150)

    if not latencia:
        return  # sin datos de latencia no se toca su gráfico
    fig, ax = plt.subplots(figsize=(5.5, 4))
    x = [f["tamano_log"] for f in latencia]
    ax.plot(x, [f["consulta_ms_p50"] for f in latencia], marker="o", label="consulta en el servidor (p50)")
    ax.plot(x, [f["verificacion_ms_p50"] for f in latencia], marker="o", label="verificar la prueba (p50)")
    ax.set_xlabel("Entradas en el log")
    ax.set_ylabel("ms")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURAS / "exp3_latencia.png", dpi=150)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--qrs", type=int, default=40)
    p.add_argument("--escaneos", type=int, default=10)
    p.add_argument("--semilla", type=int, default=7)
    p.add_argument("--sin-latencia", action="store_true")
    a = p.parse_args()
    deteccion = [fila for esc in ESCENARIOS for fila in experimento_deteccion(a.qrs, a.escaneos, a.semilla, esc)]
    guardar("exp3_deteccion.csv", deteccion)
    latencia = [] if a.sin_latencia else experimento_latencia(a.semilla)
    if latencia:
        guardar("exp3_latencia.csv", latencia)
    graficos(deteccion, latencia)


if __name__ == "__main__":
    main()
