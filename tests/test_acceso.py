"""Fase 8: código de acceso de la demo pública."""

import time

import pytest
from fastapi.testclient import TestClient

from qrsandbox.api import acceso, main, seguridad
from qrsandbox.api import analisis as A

from .test_api_analisis import CSRF, entorno, lineas  # noqa: F401 (fixture)

CODIGO = "Pr3sentacion-QR"


@pytest.fixture
def demo(monkeypatch):
    monkeypatch.setenv("DEMO_ACCESS_CODE", CODIGO)
    monkeypatch.setattr(acceso, "limite_intentos", seguridad.LimiteTasa(1, 5))
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(lineas(url)))


def nuevo_cliente():
    # base_url https: la cookie es Secure y TestClient solo la reenvía por https.
    return TestClient(main.app, headers=CSRF, base_url="https://testserver")


def test_sin_modo_demo_no_se_pide_codigo(monkeypatch):
    monkeypatch.delenv("DEMO_ACCESS_CODE", raising=False)
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(lineas(url)))
    c = nuevo_cliente()
    assert c.get("/acceso/estado").json() == {"requerido": False, "ok": True}
    assert c.post("/analisis", json={"url": "https://example.com"}).status_code == 202


def test_sin_codigo_no_se_lanzan_analisis_ni_registros(demo):
    c = nuevo_cliente()
    assert c.get("/acceso/estado").json() == {"requerido": True, "ok": False}
    r = c.post("/analisis", json={"url": "https://example.com"})
    assert r.status_code == 401 and "código de acceso" in r.json()["detail"]
    assert c.post("/log/registros", json={}).status_code == 401
    assert c.post("/log/revocaciones", json={}).status_code == 401
    # Lo público sigue abierto: páginas, salud y lectura del log.
    for ruta in ("/", "/log", "/ayuda", "/health", "/log/sth"):
        assert c.get(ruta).status_code == 200


def test_codigo_correcto_entrega_cookie_segura_y_habilita(demo):
    c = nuevo_cliente()
    assert c.post("/acceso", json={"codigo": "otro"}).status_code == 401
    r = c.post("/acceso", json={"codigo": CODIGO})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    for atributo in ("httponly", "secure", "samesite=strict", "path=/", "max-age=43200"):
        assert atributo in cookie, atributo
    assert c.get("/acceso/estado").json()["ok"] is True
    assert c.post("/analisis", json={"url": "https://example.com"}).status_code == 202


def test_cookie_alterada_vencida_o_de_otro_arranque_no_sirve(demo, monkeypatch):
    token = acceso.emitir_token()
    ts, firma = token.split(".")
    assert acceso.token_valido(token)
    assert not acceso.token_valido(f"{int(ts) + 1}.{firma}")  # alargar la vigencia
    assert not acceso.token_valido(f"{ts}.{'0' * 64}")
    assert not acceso.token_valido("basura")
    assert not acceso.token_valido(acceso.emitir_token(time.time() - acceso.DURACION_S - 10))
    monkeypatch.setattr(acceso, "_SECRETO", b"otro-arranque" * 3)  # reinicio de la API
    assert not acceso.token_valido(token)
    c = nuevo_cliente()
    c.cookies.set(acceso.COOKIE, "123.abc", domain="testserver")
    assert c.post("/analisis", json={"url": "https://example.com"}).status_code == 401


def test_fuerza_bruta_limitada(demo):
    c = nuevo_cliente()
    codigos = [c.post("/acceso", json={"codigo": f"intento{i}"}).status_code for i in range(7)]
    assert codigos[:5] == [401] * 5 and codigos[5:] == [429, 429]
    # Ni siquiera el código correcto pasa mientras dura el bloqueo.
    assert c.post("/acceso", json={"codigo": CODIGO}).status_code == 429


def test_ingresar_codigo_tambien_exige_anti_csrf(demo):
    c = TestClient(main.app, base_url="https://testserver")
    assert c.post("/acceso", json={"codigo": CODIGO}).status_code == 403


def test_ip_real_del_cliente_solo_en_modo_demo(demo, monkeypatch):
    from starlette.requests import Request

    def peticion(cabeceras):
        return Request({"type": "http", "client": ("172.18.0.5", 1),
                        "headers": [(k.encode(), v.encode()) for k, v in cabeceras.items()]})

    assert acceso.ip_cliente(peticion({"cf-connecting-ip": "200.1.2.3"})) == "200.1.2.3"
    assert acceso.ip_cliente(peticion({"cf-connecting-ip": "no-es-ip"})) == "172.18.0.5"
    monkeypatch.delenv("DEMO_ACCESS_CODE")
    assert acceso.ip_cliente(peticion({"cf-connecting-ip": "200.1.2.3"})) == "172.18.0.5"


def test_limite_por_persona_detras_del_tunel(demo, monkeypatch):
    """Todos llegan desde la IP de cloudflared: el límite debe ser por IP real."""
    monkeypatch.setattr(seguridad, "limite_analisis", seguridad.LimiteTasa(por_minuto=1, rafaga=2))
    c = nuevo_cliente()
    c.post("/acceso", json={"codigo": CODIGO})

    def lanzar(ip):
        return c.post("/analisis", json={"url": "https://a.cl"}, headers={"CF-Connecting-IP": ip}).status_code

    assert [lanzar("200.0.0.1") for _ in range(3)] == [202, 202, 429]
    assert lanzar("200.0.0.2") == 202  # otra persona no queda bloqueada


def test_limite_global(demo, monkeypatch):
    monkeypatch.setattr(seguridad, "limite_global", seguridad.LimiteTasa(por_minuto=1, rafaga=2))
    c = nuevo_cliente()
    c.post("/acceso", json={"codigo": CODIGO})
    codigos = [c.post("/analisis", json={"url": "https://a.cl"}, headers={"CF-Connecting-IP": f"200.0.0.{i}"}).status_code
               for i in range(3)]
    assert codigos == [202, 202, 429]


def test_hsts_solo_si_llega_por_https():
    c = TestClient(main.app)
    assert "strict-transport-security" not in c.get("/health").headers
    r = c.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert r.headers["strict-transport-security"] == "max-age=86400"
