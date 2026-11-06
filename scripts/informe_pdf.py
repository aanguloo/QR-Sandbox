"""Genera docs/informe.pdf a partir de docs/informe.md.

    python scripts/informe_pdf.py

Markdown -> HTML (biblioteca `markdown`) -> PDF con el Chromium de la imagen del worker
(no instala nada en el sistema). Informa la cantidad de páginas (el informe debe tener 5–10).
"""

import re
import tempfile
from pathlib import Path

import docker
import markdown

RAIZ = Path(__file__).resolve().parent.parent
FUENTE = RAIZ / "docs" / "informe.md"
DESTINO = RAIZ / "docs" / "informe.pdf"

CSS = """
@page { size: A4; margin: 2cm 2cm 2.2cm; }
body { font-family: 'DejaVu Serif', Georgia, serif; font-size: 10pt; line-height: 1.38; color: #111; }
h1 { font-size: 17pt; line-height: 1.2; margin: 0 0 6pt; }
h2 { font-size: 13pt; margin: 16pt 0 6pt; border-bottom: 1px solid #bbb; padding-bottom: 2pt; }
h3 { font-size: 11pt; margin: 12pt 0 4pt; }
h2, h3 { break-after: avoid; }
p, li { text-align: justify; hyphens: auto; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.8pt; }
table { border-collapse: collapse; width: 100%; font-size: 8.8pt; margin: 6pt 0; break-inside: avoid; }
th, td { border: 1px solid #999; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #eee; }
img { display: block; max-width: 100%; max-height: 8.8cm; margin: 6pt auto 2pt; break-inside: avoid; }
p:has(> img) { text-align: center; font-size: 9pt; color: #333; break-inside: avoid; }
img[src*="arquitectura"] { max-height: 12.5cm; }
blockquote { border-left: 3px solid #c90; background: #fff8e6; margin: 8pt 0; padding: 4pt 8pt; }
a { color: #1f4fd1; text-decoration: none; }
"""

SCRIPT = r'''
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        nav = await p.chromium.launch()
        pg = await nav.new_page()
        await pg.goto("file:///repo/docs/_informe.html")
        await pg.wait_for_load_state("networkidle")
        await pg.pdf(path="/salida/informe.pdf", format="A4", print_background=True,
                     display_header_footer=True, header_template="<span></span>",
                     footer_template="<div style='font-size:8px;width:100%;text-align:center;color:#666'>"
                                     "<span class='pageNumber'></span> / <span class='totalPages'></span></div>",
                     margin={"top": "2cm", "bottom": "2.2cm", "left": "2cm", "right": "2cm"})
        await nav.close()

asyncio.run(main())
'''


def main() -> None:
    texto = FUENTE.read_text()
    # Las imágenes "![Figura N. ...](ruta)" muestran su texto alternativo como pie de figura.
    texto = re.sub(r"!\[(Figura[^\]]*)\]\(([^)]+)\)", r"![\1](\2)  \n*\1*", texto)
    cuerpo = markdown.markdown(texto, extensions=["tables", "sane_lists"])
    html = (f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Informe QR-Sandbox</title>"
            f"<style>{CSS}</style></head><body>{cuerpo}</body></html>")
    temporal = RAIZ / "docs" / "_informe.html"
    temporal.write_text(html)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o777)
            (Path(tmp) / "pdf.py").write_text(SCRIPT)
            (Path(tmp) / "pdf.py").chmod(0o644)
            docker.from_env().containers.run(
                "qrsandbox-worker:dev", ["/salida/pdf.py"], entrypoint="python", network_mode="none",
                remove=True, volumes={str(RAIZ): {"bind": "/repo", "mode": "ro"},
                                      tmp: {"bind": "/salida", "mode": "rw"}})
            datos = (Path(tmp) / "informe.pdf").read_bytes()
    finally:
        temporal.unlink(missing_ok=True)
    DESTINO.write_bytes(datos)
    paginas = len(re.findall(rb"/Type\s*/Page[^s]", datos))
    print(f"{DESTINO.relative_to(RAIZ)}: {paginas} páginas, {len(datos) // 1024} KB")


if __name__ == "__main__":
    main()
