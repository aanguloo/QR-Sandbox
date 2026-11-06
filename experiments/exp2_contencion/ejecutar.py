"""Experimento 2: contención del sandbox con tres perfiles (basico, endurecido, gvisor).

    # 1) levantar el laboratorio (páginas hostiles propias, solo red local):
    docker compose -f docker-compose.yml -f experiments/exp2_contencion/compose.lab.yml up -d --wait
    # 2) correr:
    python experiments/exp2_contencion/ejecutar.py [--partes paginas,escape,arranque]
    # 3) volver al modo normal: make up

A. paginas:   páginas hostiles analizadas por el pipeline real (worker + proxy + orquestador).
B. escape:    un worker COMPROMETIDO (código del atacante ya corriendo en el contenedor).
C. arranque:  costo de cada perfil (tiempo de arranque de un contenedor mínimo).
D. inundador: un worker comprometido inunda su stdout (300 mil eventos + líneas gigantes).

Ética: todo es local (red Docker interna + laboratorio propio). Las pruebas tienen topes.
"basico" corre como root: es lo que hace Docker por defecto con imágenes sin USER.
Salidas: experiments/results/exp2_{paginas,escape,arranque}.csv y figures/exp2_*.png.
"""

import argparse
import csv
import json
import statistics
import time
from pathlib import Path

import docker

from qrsandbox.orquestador.ejecutor import ConfigWorker, ejecutar, parametros_contenedor

AQUI = Path(__file__).resolve().parent
RESULTADOS = AQUI.parent / "results"
FIGURAS = AQUI.parent / "figures"
PERFILES = ["basico", "endurecido", "gvisor"]
LAB = "http://172.31.250.20:8080"
PAGINAS = {
    "ssrf": "/ssrf.html",
    "memoria": "/memoria.html",
    "cpu": "/cpu.html",
    "hilos": "/hilos.html",
    "disco": "/disco.html",
    "bucle_http": "/bucle",
    "bucle_js": "/bucle_js.html",
    "descarga": "/descarga.html",
    "permisos": "/permisos.html",
    "inundacion": "/inundacion.html",
}


def proxy(cliente):
    c = cliente.containers.list(filters={"label": "com.docker.compose.service=proxy"})
    if not c:
        raise SystemExit("El proxy no está corriendo: levanta el stack con el laboratorio.")
    return c[0]


def log_proxy(contenedor, desde):
    entradas = []
    for linea in contenedor.logs(since=int(desde) - 1, stdout=True, stderr=False).decode().splitlines():
        try:
            e = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if e.get("t", 0) >= desde - 0.5:
            entradas.append(e)
    return entradas


def parte_paginas(cliente, solo=None):
    filas = []
    p = proxy(cliente)
    for perfil in PERFILES:
        for nombre, ruta in PAGINAS.items():
            if solo and nombre not in solo:
                continue
            desde = time.time()
            r = ejecutar(LAB + ruta, ConfigWorker(perfil=perfil), cliente)
            log = log_proxy(p, desde)
            bloqueos = [e for e in log if e["accion"] == "bloqueado"]
            res = r.resultado
            filas.append({
                "perfil": perfil, "pagina": nombre, "duracion_ms": r.duracion_ms,
                "codigo_salida": r.codigo_salida, "timeout": r.timeout, "salida_excedida": r.salida_excedida,
                "error": r.error or "", "contenedor_eliminado": r.contenedor_eliminado,
                "eventos": len(r.eventos), "descartados_esquema": r.eventos_descartados,
                "descartados_tasa": r.descartados_tasa, "agrupados": json.dumps(r.agrupados),
                "frames": r.frames, "proxy_bloqueos": len(bloqueos),
                "motivos_bloqueo": ",".join(sorted({e["motivo"] for e in bloqueos})),
                "titulo": (res.titulo if res else "")[:60],
                "permisos": ",".join(res.permisos) if res else "",
                "descargas_bloqueadas": sum(1 for e in r.eventos if e["tipo"] == "descarga_bloqueada"),
                "errores_worker": " | ".join(e.get("mensaje", "")[:60] for e in r.eventos if e["tipo"] == "error")[:200],
            })
            f = filas[-1]
            print(f"[páginas] {perfil:>10} {nombre:>11}: {f['duracion_ms']:>6} ms, timeout={f['timeout']}, "
                  f"bloqueos proxy={f['proxy_bloqueos']}, título «{f['titulo']}», eliminado={f['contenedor_eliminado']}")
            time.sleep(2)  # ritmo tranquilo
    return filas


def _params(perfil, comando, nombre):
    params = parametros_contenedor(ConfigWorker(perfil=perfil), perfil, "https://x.invalid/", nombre)
    params.update(entrypoint="python", command=comando,
                  volumes={str(AQUI / "escape.py"): {"bind": "/exp/escape.py", "mode": "ro"}})
    params.pop("environment", None)
    if perfil == "basico":
        params["user"] = "0:0"  # Docker por defecto: root dentro del contenedor
    return params


# Las pruebas de memoria y fork bomb van en contenedores aparte: con gVisor, exceder la
# memoria termina el SANDBOX COMPLETO (no solo el proceso), y eso cortaba las demás pruebas.
GRUPOS = [("memoria", ["memoria"], "reservar 1,5 GB de memoria"),
          ("procesos", ["procesos"], "fork bomb (hasta 1500 procesos)"),
          ("resto", [], None)]


def parte_escape(cliente):
    filas = []
    for perfil in PERFILES:
        for grupo, args, prueba_esperada in GRUPOS:
            nombre = f"qrs-exp2-escape-{perfil}-{grupo}"
            c = cliente.containers.run(**_params(perfil, ["/exp/escape.py", *args], nombre))
            try:
                estado = c.wait(timeout=180)
                c.reload()
                oom = c.attrs["State"].get("OOMKilled", False)
                salida = c.logs(stdout=True, stderr=False).decode()
            finally:
                c.remove(force=True)
            vistas = []
            for linea in salida.splitlines():
                try:
                    d = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                vistas.append(d["prueba"])
                filas.append({"perfil": perfil, **d})
            if prueba_esperada and prueba_esperada not in vistas:
                filas.append({"perfil": perfil, "prueba": prueba_esperada, "bloqueado": True, "contenido": False,
                              "detalle": f"el contenedor completo fue terminado (código {estado['StatusCode']}, OOMKilled={oom})"})
    for f in filas:
        estado = "contenido" if f["contenido"] else "BLOQUEADO" if f["bloqueado"] else "permitido"
        print(f"[escape] {f['perfil']:>10} {f['prueba']:<45} {estado:<10} {f['detalle'][:80]}")
    return filas


def parte_arranque(cliente, repeticiones=10):
    filas = []
    for perfil in PERFILES:
        tiempos = []
        for i in range(repeticiones):
            params = _params(perfil, ["-c", "pass"], f"qrs-exp2-arranque-{perfil}-{i}")
            params.pop("volumes")
            params["detach"] = False
            params["remove"] = True
            t0 = time.perf_counter()
            cliente.containers.run(**params)
            tiempos.append((time.perf_counter() - t0) * 1000)
        filas.append({"perfil": perfil, "repeticiones": repeticiones,
                      "arranque_ms_p50": round(statistics.median(tiempos)),
                      "arranque_ms_p95": round(sorted(tiempos)[int(0.95 * repeticiones) - 1]),
                      "arranque_ms_min": round(min(tiempos))})
        print(f"[arranque] {perfil:>10}: p50 {filas[-1]['arranque_ms_p50']} ms")
    return filas


def parte_inundador(cliente):
    """Worker comprometido que inunda su stdout: ¿el orquestador aguanta y lo corta?"""
    cliente.images.build(path=str(AQUI / "inundador"), tag="qrsandbox-inundador:exp", rm=True)
    filas = []
    for perfil in PERFILES:
        import tracemalloc

        tracemalloc.start()
        r = ejecutar("https://x.invalid/", ConfigWorker(perfil=perfil, imagen="qrsandbox-inundador:exp"), cliente)
        _, pico = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        filas.append({
            "perfil": perfil, "duracion_ms": r.duracion_ms, "salida_excedida": r.salida_excedida,
            "bytes_leidos": r.metricas.get("bytes_salida_worker"), "eventos_aceptados": len(r.eventos),
            "descartados_esquema": r.eventos_descartados, "descartados_tasa": r.descartados_tasa,
            "agrupados": json.dumps(r.agrupados), "contenedor_eliminado": r.contenedor_eliminado,
            "memoria_pico_orquestador_mb": round(pico / 1e6, 1),
        })
        f = filas[-1]
        print(f"[inundador] {perfil:>10}: cortado={f['salida_excedida']} tras {f['bytes_leidos']} bytes en "
              f"{f['duracion_ms']} ms; aceptados {f['eventos_aceptados']}, agrupados {f['agrupados']}, "
              f"memoria pico {f['memoria_pico_orquestador_mb']} MB, eliminado={f['contenedor_eliminado']}")
    return filas


def guardar(nombre, filas):
    if not filas:
        return
    RESULTADOS.mkdir(parents=True, exist_ok=True)
    with (RESULTADOS / nombre).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)


def graficos(escape, arranque):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap

    FIGURAS.mkdir(parents=True, exist_ok=True)
    if escape:
        pruebas = list(dict.fromkeys(f["prueba"] for f in escape))
        celda = {(f["prueba"], f["perfil"]): f for f in escape}
        def valor(f):
            if "esperado" in f.get("detalle", ""):
                return 3  # el proxy: conectar es lo esperado (única salida, filtrada)
            return 2 if f.get("contenido") else 1 if f.get("bloqueado") else 0

        matriz = [[valor(celda.get((p, perf), {})) for perf in PERFILES] for p in pruebas]
        fig, ax = plt.subplots(figsize=(8, 0.42 * len(pruebas) + 1.2))
        ax.imshow(matriz, cmap=ListedColormap(["#f4b4ad", "#9fd8b0", "#f6e3a1", "#dfe3e8"]), aspect="auto", vmin=0, vmax=3)
        ax.set_xticks(range(len(PERFILES)), PERFILES)
        ax.set_yticks(range(len(pruebas)), pruebas, fontsize=8)
        ax.xaxis.tick_top()
        for i, p in enumerate(pruebas):
            for j, perf in enumerate(PERFILES):
                f = celda.get((p, perf))
                if f:
                    texto = ("permitido (esperado)" if "esperado" in f["detalle"] else "contenido (gVisor)"
                             if f.get("contenido") else "bloqueado" if f["bloqueado"] else "permitido")
                    ax.text(j, i, texto, ha="center", va="center", fontsize=7)
        ax.set_title("Worker comprometido: ¿qué logra el atacante?\n(verde = bloqueado, amarillo = solo dentro de gVisor, rojo = permitido)",
                     fontsize=9, pad=28)
        fig.tight_layout()
        fig.savefig(FIGURAS / "exp2_escape.png", dpi=150)
    if arranque:
        fig, ax = plt.subplots(figsize=(5, 3.5))
        ax.bar([f["perfil"] for f in arranque], [f["arranque_ms_p50"] for f in arranque], color=["#9aa5b1", "#5b8def", "#1f4fd1"])
        for i, f in enumerate(arranque):
            ax.text(i, f["arranque_ms_p50"], f"{f['arranque_ms_p50']} ms", ha="center", va="bottom")
        ax.set_ylabel("Arranque de un contenedor (ms, p50)")
        ax.set_title("Costo de cada perfil de aislamiento")
        fig.tight_layout()
        fig.savefig(FIGURAS / "exp2_arranque.png", dpi=150)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--partes", default="escape,arranque,paginas,inundador")
    p.add_argument("--paginas", help="solo estas páginas (separadas por coma)")
    a = p.parse_args()
    partes = a.partes.split(",")
    cliente = docker.from_env()
    escape = arranque = []
    if "escape" in partes:
        escape = parte_escape(cliente)
        guardar("exp2_escape.csv", escape)
    if "arranque" in partes:
        arranque = parte_arranque(cliente)
        guardar("exp2_arranque.csv", arranque)
    if "paginas" in partes:
        nuevas = parte_paginas(cliente, a.paginas.split(",") if a.paginas else None)
        if a.paginas and (RESULTADOS / "exp2_paginas.csv").exists():
            # Repetir solo algunas páginas: se reemplazan sus filas en el CSV existente.
            previas = list(csv.DictReader((RESULTADOS / "exp2_paginas.csv").open()))
            hechas = {(f["perfil"], f["pagina"]) for f in nuevas}
            nuevas = [f for f in previas if (f["perfil"], f["pagina"]) not in hechas] + nuevas
            orden = {n: i for i, n in enumerate(PAGINAS)}
            nuevas.sort(key=lambda f: (PERFILES.index(f["perfil"]), orden[f["pagina"]]))
        guardar("exp2_paginas.csv", nuevas)
    if "inundador" in partes:
        guardar("exp2_inundador.csv", parte_inundador(cliente))
    graficos(escape, arranque)


if __name__ == "__main__":
    main()
