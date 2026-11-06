"""Renderiza docs/diagramas/*.mmd (Mermaid) a PNG y SVG para el informe.

    python scripts/render_diagramas.py

Usa el Chromium que ya trae la imagen del worker (no instala nada en el sistema) y una
copia de mermaid.min.js descargada a data/herramientas/ (no se versiona).
"""

import shutil
import tempfile
from pathlib import Path

import docker
import httpx

RAIZ = Path(__file__).resolve().parent.parent
DIAGRAMAS = RAIZ / "docs" / "diagramas"
MERMAID = RAIZ / "data" / "herramientas" / "mermaid-11.4.1.min.js"
URL_MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"

SCRIPT = r'''
import asyncio, pathlib
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        nav = await p.chromium.launch()
        pg = await nav.new_page(device_scale_factor=2, viewport={"width": 1600, "height": 1200})
        await pg.set_content("<html><body style='margin:0;background:#fff'><div id=d></div></body></html>")
        await pg.add_script_tag(path="/mermaid/mermaid.min.js")
        await pg.evaluate("""mermaid.initialize({startOnLoad: false, theme: 'neutral',
            fontFamily: 'DejaVu Sans, sans-serif', flowchart: {htmlLabels: true, curve: 'basis'},
            sequence: {mirrorActors: false}})""")
        for mmd in sorted(pathlib.Path("/diagramas").glob("*.mmd")):
            svg = await pg.evaluate("async (c) => (await mermaid.render('g' + Date.now(), c)).svg", mmd.read_text())
            await pg.evaluate("(s) => { document.getElementById('d').innerHTML = s; }", svg)
            pathlib.Path(f"/salida/{mmd.stem}.svg").write_text(svg)
            await pg.locator("#d svg").screenshot(path=f"/salida/{mmd.stem}.png")
            print("ok", mmd.stem)
        await nav.close()

asyncio.run(main())
'''


def main() -> None:
    if not MERMAID.exists():
        MERMAID.parent.mkdir(parents=True, exist_ok=True)
        MERMAID.write_bytes(httpx.get(URL_MERMAID, follow_redirects=True, timeout=60).content)
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o755)  # el contenedor (UID 10001) debe poder leer el script
        salida = Path(tmp) / "salida"
        salida.mkdir(mode=0o777)
        salida.chmod(0o777)  # el contenedor corre como UID 10001
        (Path(tmp) / "render.py").write_text(SCRIPT)
        (Path(tmp) / "render.py").chmod(0o644)
        log = docker.from_env().containers.run(
            "qrsandbox-worker:dev", ["/tmp-render/render.py"], entrypoint="python",
            network_mode="none", remove=True,
            volumes={str(DIAGRAMAS): {"bind": "/diagramas", "mode": "ro"},
                     str(MERMAID): {"bind": "/mermaid/mermaid.min.js", "mode": "ro"},
                     tmp: {"bind": "/tmp-render", "mode": "ro"},
                     str(salida): {"bind": "/salida", "mode": "rw"}},
        )
        print(log.decode().strip())
        for f in salida.iterdir():
            shutil.copy(f, DIAGRAMAS / f.name)


if __name__ == "__main__":
    main()
