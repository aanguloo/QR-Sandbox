"""Corre DENTRO de la imagen del worker (tiene Chromium). Imprime un JSON con lo observado.

    python xss.py <base_url> <id_analisis>
"""
import asyncio
import json
import sys

from playwright.async_api import async_playwright


async def main(base: str, id_analisis: str) -> None:
    salida = {"paginas": {}}
    async with async_playwright() as p:
        navegador = await p.chromium.launch()
        contexto = await navegador.new_context()
        for ruta in ("/", "/comercio", "/log", "/ayuda", f"/analisis/{id_analisis}"):
            pagina = await contexto.new_page()
            mensajes, errores, dialogos = [], [], []
            pagina.on("console", lambda m, l=mensajes: l.append(f"{m.type}: {m.text}"))
            pagina.on("pageerror", lambda e, l=errores: l.append(str(e)))
            pagina.on("dialog", lambda d, l=dialogos: (l.append(d.message), asyncio.ensure_future(d.dismiss())))
            await pagina.goto(base + ruta, wait_until="load")
            info = {}
            if ruta.startswith("/analisis/"):
                await pagina.wait_for_selector("#veredicto:not(.oculto)", timeout=20000)
                await pagina.wait_for_timeout(500)
                info = {
                    "xss": await pagina.evaluate("typeof window.__xss"),
                    "titulo_mostrado": await pagina.locator("#detalles code").first.text_content(),
                    "scripts": await pagina.evaluate("document.scripts.length"),
                    "imgs_inyectadas": await pagina.evaluate("document.querySelectorAll('img[src=\"x\"]').length"),
                    "linea": await pagina.locator("#linea").inner_text(),
                    "veredicto": await pagina.locator("#veredicto .estado").inner_text(),
                    "pantalla_src": await pagina.locator("#pantalla").get_attribute("src"),
                }
            else:
                await pagina.wait_for_timeout(800)
            salida["paginas"][ruta] = {
                "csp": [m for m in mensajes if "Content Security Policy" in m],
                "errores": errores, "dialogos": dialogos, **info,
            }
            await pagina.close()
        await navegador.close()
    print(json.dumps(salida))


asyncio.run(main(sys.argv[1], sys.argv[2]))
