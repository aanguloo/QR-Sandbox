"""Recorrido completo del comercio en un Chromium real (corre dentro de la imagen del worker).

    python flujo_comercio.py <base_url>     -> imprime JSON con lo observado
1. Crea clave, registra un QR (clic en el centro del mapa) y verifica el recibo.
2. Desde la misma página lanza un análisis de ese QR en esa ubicación (fetch con la
   cabecera anti-CSRF, como la web real) y abre el resultado: log verificado en el navegador.
3. Explorador del log (firmas, inclusión, consistencia) y revocación del QR.
"""
import asyncio
import json
import sys

from playwright.async_api import async_playwright

URL_QR = "https://pagos.ejemplo.cl/mesa/4"


LANZAR = """async ([url, lat, lon]) => {
  const r = await fetch('/analisis', {method: 'POST', body: JSON.stringify({url, lat, lon}),
    headers: {'Content-Type': 'application/json', 'X-QRSandbox-CSRF': '1'}});
  return (await r.json()).id;
}"""


async def main(base: str) -> None:
    out: dict = {}
    async with async_playwright() as p:
        nav = await p.chromium.launch()
        ctx = await nav.new_context()
        pg = await ctx.new_page()
        errores = []
        pg.on("pageerror", lambda e: errores.append(str(e)))
        pg.on("dialog", lambda d: asyncio.ensure_future(d.accept("Cambiamos de proveedor")))
        if True:
            await pg.goto(base + "/comercio")
            await pg.click("#boton-generar")
            await pg.wait_for_selector("#estado-clave code")
            out["clave"] = await pg.locator("#estado-clave code").text_content()
            await pg.locator("#mapa").click()  # centro del mapa = Plaza de Armas
            out["coordenadas"] = await pg.locator("#coordenadas").text_content()
            await pg.fill("#url-destino", URL_QR)
            await pg.fill("#descripcion", "Carta QR mesa 4")
            await pg.click("#boton-registrar")
            await pg.wait_for_selector("#mensaje-registro .mensaje-ok, #mensaje-registro .mensaje-error", timeout=15000)
            out["registro"] = await pg.locator("#mensaje-registro").inner_text()
            out["canvas_qr"] = await pg.locator("#resultado-registro canvas").count()
            await pg.wait_for_selector("#mis-qrs .etiqueta")
            out["mis_qrs"] = await pg.locator("#mis-qrs").inner_text()
            lat, lon = (float(x) for x in out["coordenadas"].split(","))
            id_analisis = await pg.evaluate(LANZAR, [URL_QR, round(lat, 4), round(lon, 4)])
            await pg.goto(f"{base}/analisis/{id_analisis}")
            await pg.wait_for_selector("#log:not(.oculto) .mensaje", timeout=20000)
            out["log"] = await pg.locator("#log").inner_text()
            await pg.goto(base + "/log")
            await pg.wait_for_selector("#seccion-sth .mensaje")
            out["sth"] = await pg.locator("#seccion-sth").inner_text()
            await pg.locator("#lista button").first.click()
            await pg.wait_for_selector("#lista .etiqueta")
            out["verificacion_fila"] = await pg.locator("#lista tbody tr").first.inner_text()
            await pg.goto(base + "/comercio")
            await pg.wait_for_selector("#mis-qrs button.peligro")
            await pg.click("#mis-qrs button.peligro")
            await pg.wait_for_selector("#mis-qrs .etiqueta.alerta", timeout=15000)
            out["revocacion"] = await pg.locator("#mensaje-registro").inner_text()
            out["mis_qrs_despues"] = await pg.locator("#mis-qrs").inner_text()
            # La revocación agregó la entrada #1: el log de 2 entradas debe extender al de 1.
            await pg.goto(base + "/log")
            await pg.wait_for_selector("#seccion-sth .mensaje")
            out["sth_despues"] = await pg.locator("#seccion-sth").inner_text()
            await pg.fill("#tam-a", "1")
            await pg.fill("#tam-b", "2")
            await pg.click("#form-consistencia button")
            await pg.wait_for_selector("#resultado-consistencia .mensaje")
            out["consistencia"] = await pg.locator("#resultado-consistencia").inner_text()
        out["errores"] = errores
        await nav.close()
    print(json.dumps(out, ensure_ascii=False))


asyncio.run(main(sys.argv[1]))
