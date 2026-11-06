"""Fase 5: análisis asíncrono con canal en vivo (SSE). Orquestador simulado."""

import base64
import io
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from PIL import Image

from qrsandbox.api import analisis as A
from qrsandbox.api import main, seguridad
from qrsandbox.api.log import obtener_log
from qrsandbox.tlog.log import LogTransparencia
from qrsandbox.tlog.registro import firmar_registro

CSRF = {"X-QRSandbox-CSRF": "1"}
cliente = TestClient(main.app, headers=CSRF)
TITULO_MALICIOSO = '<script>window.__xss=1</script><img src=x onerror="window.__xss=1">'


def jpeg() -> bytes:
    b = io.BytesIO()
    Image.new("RGB", (39, 84), (200, 0, 0)).save(b, format="JPEG")
    return b.getvalue()


def resultado(url: str, titulo: str = "Example Domain") -> dict:
    return {
        "id": "0123456789ab", "url": url, "runtime": "runsc", "perfil": "gvisor",
        "duracion_ms": 1500, "codigo_salida": 0, "timeout": False, "salida_excedida": False,
        "eventos": [{"tipo": "navegacion", "t_ms": 5, "url": url}], "eventos_descartados": 0,
        "resultado": {
            "url_inicial": url, "url_final": url, "cadena_redirecciones": [url], "titulo": titulo,
            "estado_http": 200, "formularios_password": 0, "dominios_terceros": [],
            "n_dominios_terceros": 0, "tiempo_carga_ms": 300,
        },
        "captura_jpeg_b64": base64.b64encode(jpeg()).decode(), "contenedor_eliminado": True,
    }


def lineas(url: str, titulo: str = "Example Domain", extra=()) -> list[bytes]:
    eventos = [
        {"tipo": "navegacion", "t_ms": 5, "url": url},
        *extra,
        {"tipo": "captura", "t_ms": 6, "jpeg_b64": base64.b64encode(jpeg()).decode()},
        {"tipo": "fin", "t_ms": 7, "resultado": None},
        {"tipo": "resultado", "datos": resultado(url, titulo)},
    ]
    return [json.dumps(e).encode() for e in eventos]


@pytest.fixture(autouse=True)
def entorno(tmp_path, monkeypatch):
    """Log temporal (nunca data/tlog.sqlite real) y almacén y límite de tasa nuevos."""
    log = LogTransparencia(tmp_path / "tlog.sqlite", Ed25519PrivateKey.generate())
    main.app.dependency_overrides[obtener_log] = lambda: log
    monkeypatch.setattr(A, "almacen", A.Almacen())
    monkeypatch.setattr(seguridad, "limite_analisis", seguridad.LimiteTasa(1000, 1000))
    yield log
    main.app.dependency_overrides.clear()


@pytest.fixture
def orquestador_falso(monkeypatch):
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(lineas(url)))


def eventos_sse(id_analisis: str) -> list[tuple[str, dict]]:
    with cliente.stream("GET", f"/analisis/{id_analisis}/eventos") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        texto = "".join(r.iter_text())
    salida = []
    for bloque in texto.strip().split("\n\n"):
        if bloque.lstrip().startswith(":"):
            continue  # comentarios SSE (relleno y latidos)
        campos = dict(linea.split(": ", 1) for linea in bloque.splitlines() if ": " in linea)
        salida.append((campos["event"], json.loads(campos["data"])))
    return salida


# ------------------------------------------------------------------ validación de entrada


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://x.cl", "no-es-url", "https://"]
)
def test_rechaza_urls_no_http(url, orquestador_falso):
    assert cliente.post("/analisis", json={"url": url}).status_code == 422


def test_rechaza_campos_extra_y_lat_sin_lon(orquestador_falso):
    assert cliente.post("/analisis", json={"url": "https://a.cl", "runtime": "x"}).status_code == 422
    assert cliente.post("/analisis", json={"url": "https://a.cl", "lat": 1.0}).status_code == 422


# ------------------------------------------------------------------ flujo asíncrono + SSE


def test_analisis_asincrono_con_eventos_en_vivo(orquestador_falso):
    r = cliente.post("/analisis", json={"url": "https://example.com"})
    assert r.status_code == 202
    datos = r.json()
    assert len(datos["id"]) == 32 and datos["pagina"] == f"/analisis/{datos['id']}"

    eventos = eventos_sse(datos["id"])
    tipos = [t for t, _ in eventos]
    assert "evento" in tipos and "frame" in tipos and tipos[-1] == "fin"
    frame = next(d for t, d in eventos if t == "frame")
    assert base64.b64decode(frame["jpeg_b64"]).startswith(b"\xff\xd8\xff")
    fin = eventos[-1][1]
    assert fin["id"] == datos["id"] and fin["veredicto"]["estado"] == "sin_alertas"
    assert "captura_jpeg_b64" not in fin

    # Se puede reconectar: el SSE reenvía todo y vuelve a terminar con "fin".
    assert eventos_sse(datos["id"])[-1][0] == "fin"
    res = cliente.get(f"/analisis/{datos['id']}/resultado").json()
    assert res["estado"] == "terminado" and res["resultado"]["veredicto"]


def test_captura_con_tipo_fijo(orquestador_falso):
    r = cliente.post("/analisis?esperar=true", json={"url": "https://example.com"}).json()
    c = cliente.get(r["captura_url"])
    assert c.status_code == 200
    assert c.headers["content-type"] == "image/jpeg"
    assert c.headers["x-content-type-options"] == "nosniff"
    assert c.content.startswith(b"\xff\xd8\xff")


def test_eventos_invalidos_del_orquestador_se_descartan(monkeypatch):
    extra = [{"tipo": "ejecutar", "cmd": "rm -rf /"},
             {"tipo": "navegacion", "t_ms": 1, "url": "javascript:alert(1)"}]
    malas = lineas("https://example.com", extra=extra) + [b"{no json", b"x" * 500_000]
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(malas))
    r = cliente.post("/analisis", json={"url": "https://example.com"}).json()
    eventos = [d for t, d in eventos_sse(r["id"]) if t == "evento"]
    assert [e["tipo"] for e in eventos] == ["navegacion"]
    assert A.almacen.obtener(r["id"]).descartados == 2


def test_frame_que_no_es_jpeg_no_llega_al_navegador(monkeypatch):
    extra = [{"tipo": "captura", "t_ms": 2, "jpeg_b64": base64.b64encode(b"<svg onload=x>").decode()}]
    todo = [ln for ln in lineas("https://example.com") if b'"captura"' not in ln]
    todo.insert(1, json.dumps(extra[0]).encode())
    monkeypatch.setattr(A, "flujo_orquestador", lambda url: iter(todo))
    r = cliente.post("/analisis", json={"url": "https://example.com"}).json()
    frames = [d for t, d in eventos_sse(r["id"]) if t == "frame"]
    assert frames == []


def test_titulo_malicioso_viaja_como_dato_json(monkeypatch):
    """El título hostil llega al navegador solo dentro de JSON (se pinta con textContent)."""
    monkeypatch.setattr(A, "flujo_orquestador",
                        lambda url: iter(lineas(url, titulo=TITULO_MALICIOSO)))
    r = cliente.post("/analisis?esperar=true", json={"url": "https://example.com"})
    assert r.headers["content-type"] == "application/json"
    assert r.json()["resultado"]["titulo"] == TITULO_MALICIOSO


# ------------------------------------------------------------------ errores y límites


def test_orquestador_caido(monkeypatch):
    import httpx

    def caido(url):
        raise httpx.ConnectError("sin conexión")
        yield  # pragma: no cover

    monkeypatch.setattr(A, "flujo_orquestador", caido)
    assert cliente.post("/analisis?esperar=true", json={"url": "https://a.cl"}).status_code == 503
    r = cliente.post("/analisis", json={"url": "https://a.cl"}).json()
    assert eventos_sse(r["id"])[-1][0] == "fallo"


def test_limite_de_analisis_por_cliente(orquestador_falso, monkeypatch):
    monkeypatch.setattr(seguridad, "limite_analisis", seguridad.LimiteTasa(por_minuto=1, rafaga=2))
    codigos = [cliente.post("/analisis", json={"url": "https://a.cl"}).status_code for _ in range(4)]
    assert codigos == [202, 202, 429, 429]


def test_limite_de_tasa_se_recarga():
    lim = seguridad.LimiteTasa(por_minuto=60, rafaga=1)
    assert lim.permitir("x", 0) and not lim.permitir("x", 0.1)
    assert lim.permitir("x", 1.2)
    assert lim.permitir("otro", 0.1)


def test_ids_invalidos_o_desconocidos():
    for ruta in ("/analisis/zz/resultado", "/analisis/" + "a" * 32 + "/resultado",
                 "/analisis/" + "a" * 32 + "/eventos", "/analisis/..%2f..%2fetc/captura"):
        assert cliente.get(ruta).status_code == 404


def test_almacen_acotado():
    al = A.Almacen(maximo=2)
    a, b = al.crear("https://a.cl", None, None), al.crear("https://b.cl", None, None)
    with pytest.raises(A.AlmacenLleno):
        al.crear("https://c.cl", None, None)  # ambos en curso: no se descarta trabajo vivo
    a.estado = "terminado"
    al.crear("https://c.cl", None, None)
    assert al.obtener(a.id) is None and al.obtener(b.id) is b


def test_ubicacion_se_redondea_al_llegar():
    a = A.Almacen().crear("https://a.cl", -33.4378123456, -70.6505987654)
    assert (a.lat, a.lon) == (-33.438, -70.651)


# ------------------------------------------------------------------ veredicto y log


def test_analisis_incluye_veredicto_y_estado_del_log(orquestador_falso, entorno):
    entorno.agregar(firmar_registro(
        Ed25519PrivateKey.generate(), url_destino="https://pagos.ejemplo.cl/mesa/4",
        lat_e6=-33437800, lon_e6=-70650500, radio_m=30, descripcion="Mesa 4",
        timestamp=int(time.time()),
    ))
    r = cliente.post("/analisis?esperar=true", json={
        "url": "https://pagos-ejemplo.xyz/mesa/4", "lat": -33.4378, "lon": -70.6505}).json()
    assert r["log"]["estado"] == "no_coincide"
    v = r["veredicto"]
    assert v["estado"] == "peligroso"  # sticker (60) + TLD .xyz (15)
    assert v["razones"][0]["codigo"] == "log_no_coincide"

    sin_ubicacion = cliente.post("/analisis?esperar=true", json={"url": "https://example.com"}).json()
    assert sin_ubicacion["log"] is None
    assert sin_ubicacion["veredicto"]["estado"] == "sin_alertas"


def test_progreso_por_sondeo_y_frame_actual(orquestador_falso):
    """Respaldo del SSE: mismo contenido por sondeo; el frame va aparte como image/jpeg."""
    r = cliente.post("/analisis?esperar=true", json={"url": "https://example.com"}).json()
    p = cliente.get(f"/analisis/{r['id']}/progreso").json()
    assert p["estado"] == "terminado" and p["frame_seq"] >= 1
    assert [e["seq"] for e in p["eventos"]] == list(range(len(p["eventos"])))
    assert p["eventos"][-1]["tipo"] == "fin"
    resto = cliente.get(f"/analisis/{r['id']}/progreso", params={"desde": len(p["eventos"]) - 1}).json()
    assert [e["tipo"] for e in resto["eventos"]] == ["fin"]
    f = cliente.get(f"/analisis/{r['id']}/frame")
    assert f.headers["content-type"] == "image/jpeg" and f.content.startswith(b"\xff\xd8\xff")
    assert cliente.get(f"/analisis/{r['id']}/progreso", params={"desde": -1}).status_code == 422
