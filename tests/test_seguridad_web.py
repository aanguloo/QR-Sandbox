"""Fase 5: seguridad web (CSP, clickjacking, CSRF) y reglas sobre el código del navegador."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qrsandbox.api.main import app
from qrsandbox.api.seguridad import motivo_csrf

WEB = Path(__file__).resolve().parent.parent / "web"
cliente = TestClient(app)


@pytest.mark.parametrize("ruta", ["/", "/comercio", "/log", "/ayuda", "/analisis/" + "0" * 32])
def test_paginas_con_cabeceras_de_seguridad(ruta):
    r = cliente.get(ruta)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "object-src 'none'" in csp and "base-uri 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"  # anti-clickjacking (navegadores viejos)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "camera=(self)" in r.headers["permissions-policy"]


def test_cabeceras_tambien_en_json_y_errores():
    for r in (cliente.get("/health"), cliente.get("/no-existe")):
        assert r.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in r.headers["content-security-policy"]


def test_pagina_de_analisis_con_id_invalido():
    assert cliente.get("/analisis/no-es-un-id").status_code == 404


# ------------------------------------------------------------------ CSRF


def test_post_sin_cabecera_anti_csrf_se_rechaza():
    r = cliente.post("/log/normalizar", json={"url": "https://a.cl"})
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]


def test_post_tipo_formulario_se_rechaza():
    """El truco clásico: un <form> de otro sitio con enctype text/plain y cuerpo JSON."""
    r = cliente.post("/log/normalizar", content='{"url": "https://a.cl"}',
                     headers={"X-QRSandbox-CSRF": "1", "Content-Type": "text/plain"})
    assert r.status_code == 403


def test_post_desde_otro_origen_se_rechaza():
    r = cliente.post("/log/normalizar", json={"url": "https://a.cl"},
                     headers={"X-QRSandbox-CSRF": "1", "Origin": "https://malo.example"})
    assert r.status_code == 403


def test_post_legitimo_pasa():
    r = cliente.post("/log/normalizar", json={"url": "HTTPS://A.cl:443/x#y"},
                     headers={"X-QRSandbox-CSRF": "1", "Origin": "http://testserver"})
    assert r.status_code == 200 and r.json()["url"] == "https://a.cl/x"


def test_motivo_csrf_get_no_aplica():
    assert motivo_csrf("GET", {}) is None


# ------------------------------------------------------------------ reglas sobre el código web

PELIGROSAS = re.compile(
    r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function\s*\("
    r"|setTimeout\s*\(\s*['\"`]|setInterval\s*\(\s*['\"`]"
)


def test_js_propio_no_usa_apis_que_interpretan_html_o_codigo():
    """Todo texto externo se inserta con textContent. Ni innerHTML ni eval en nuestro JS."""
    archivos = list((WEB / "static" / "js").glob("*.js")) + [WEB / "sw.js"]
    assert len(archivos) >= 6
    for archivo in archivos:
        codigo = re.sub(r"//.*", "", archivo.read_text())  # sin comentarios
        assert not PELIGROSAS.search(codigo), f"{archivo.name}: {PELIGROSAS.search(codigo).group()}"


@pytest.mark.parametrize(
    "pagina", ["index.html", "analisis.html", "comercio.html", "log.html", "ayuda.html"]
)
def test_html_sin_scripts_ni_estilos_ni_handlers_inline(pagina):
    html = (WEB / pagina).read_text()
    for script in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.DOTALL):
        assert script.strip() == "", f"script inline en {pagina}"
    assert all(re.search(r'\bsrc="/static/', s) for s in re.findall(r"<script\b[^>]*>", html))
    assert not re.search(r"\son[a-z]+\s*=", html), "handler inline"
    assert not re.search(r"\sstyle\s*=", html), "estilo inline"
    assert "<style" not in html
    assert not re.search(r'(src|href)="https?://', html), "recurso de un CDN externo"


def test_cada_hallazgo_tiene_explicacion_para_no_expertos():
    from qrsandbox.senales.hallazgos import PESOS

    js = (WEB / "static" / "js" / "explicaciones.js").read_text()
    bloque = js.split("export const EXPLICACIONES = {", 1)[1].split("};", 1)[0]
    explicados = set(re.findall(r"^\s+([a-z_]+):", bloque, re.MULTILINE))
    assert set(PESOS) <= explicados, f"sin explicación: {set(PESOS) - explicados}"
