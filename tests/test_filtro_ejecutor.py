"""Fase 2: filtro anti-DoS, perfiles y robustez del ejecutor (Docker simulado)."""

import base64
import io
import json

import pytest
from docker.errors import APIError, NotFound
from PIL import Image

from qrsandbox.comun.esquemas import normalizar_url
from qrsandbox.orquestador import ejecutor
from qrsandbox.orquestador.ejecutor import ConfigWorker, parametros_contenedor, resolver_perfil
from qrsandbox.orquestador.filtro import FiltroEventos

# --- Filtro ---------------------------------------------------------------


class Reloj:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_filtro_agrupa_excedentes_por_tipo():
    f = FiltroEventos(tasa_por_s=1e9, rafaga=1e9)
    aceptados = sum(f.admitir("request_tercero") for _ in range(255))
    assert aceptados == 25
    assert f.agrupados["request_tercero"] == 230  # "+230 requests a terceros"


def test_filtro_limita_tasa_pero_nunca_descarta_fin():
    reloj = Reloj()
    f = FiltroEventos(tasa_por_s=10, rafaga=5, reloj=reloj)
    resultados = [f.admitir("navegacion") for _ in range(20)]
    assert sum(resultados) == 5
    assert f.descartados_tasa == 15
    assert f.admitir("fin")  # aunque no queden fichas
    reloj.t += 1.0  # pasa un segundo: se recargan fichas
    assert f.admitir("navegacion")


def test_filtro_limita_fps_de_capturas():
    reloj = Reloj()
    f = FiltroEventos(reloj=reloj)
    assert f.admitir("captura")
    reloj.t += 0.05
    assert not f.admitir("captura")  # 20 fps: demasiado rápido
    reloj.t += 0.3
    assert f.admitir("captura")


# --- Normalización de URLs ---------------------------------------------------


@pytest.mark.parametrize(
    ("entrada", "salida"),
    [
        ("HTTPS://Example.COM:443/a#frag", "https://example.com/a"),
        ("http://EJEMPLO.cl:80", "http://ejemplo.cl"),
        ("https://bancoestаdo.cl/login", "https://xn--bancoestdo-6qi.cl/login"),  # "а" cirílica
        ("http://[::1]:8080/", "http://[::1]:8080/"),
        ("https://usuario@malo.cl/", "https://usuario@malo.cl/"),
    ],
)
def test_normalizar_url(entrada, salida):
    assert normalizar_url(entrada) == salida


@pytest.mark.parametrize("url", ["https://a b.cl", "http://x.cl:99999", "gopher://x", "http:///x"])
def test_normalizar_url_rechaza(url):
    with pytest.raises(ValueError):
        normalizar_url(url)


# --- Perfiles ----------------------------------------------------------------


class InfoFalsa:
    def __init__(self, runtimes):
        self.runtimes = runtimes

    def info(self):
        return {"Runtimes": self.runtimes}


def test_perfil_gvisor_cae_a_endurecido_si_no_hay_runsc():
    perfil, aviso = resolver_perfil(InfoFalsa({"runc": {}}), "gvisor")
    assert perfil == "endurecido"
    assert "runsc" in aviso


def test_perfil_gvisor_se_usa_si_hay_runsc():
    assert resolver_perfil(InfoFalsa({"runc": {}, "runsc": {}}), "gvisor") == ("gvisor", None)


def test_parametros_de_endurecimiento():
    config = ConfigWorker()
    p = parametros_contenedor(config, "endurecido", "https://a.cl", "n")
    assert p["cap_drop"] == ["ALL"]
    assert p["read_only"] is True
    assert p["user"] == "10001:10001"
    assert p["mem_limit"] == "512m" and p["memswap_limit"] == "512m"
    assert p["pids_limit"] == 256
    assert p["runtime"] == "runc"
    assert "no-new-privileges:true" in p["security_opt"]
    seccomp = json.loads(next(o for o in p["security_opt"] if o.startswith("seccomp="))[8:])
    permitidas = {n for r in seccomp["syscalls"] if r["action"] == "SCMP_ACT_ALLOW" for n in r["names"]}
    assert not permitidas & {"ptrace", "process_vm_readv", "userfaultfd", "bpf", "io_uring_setup"}
    assert p["network"] == "qrsandbox_sandbox"
    assert p["environment"]["QRS_PROXY"].startswith("http://")
    assert parametros_contenedor(config, "gvisor", "https://a.cl", "n")["runtime"] == "runsc"
    basico = parametros_contenedor(config, "basico", "https://a.cl", "n")
    assert "cap_drop" not in basico and basico["network"] == "qrsandbox_sandbox"


# --- Ejecutor con Docker simulado ----------------------------------------------


class ContenedorFalso:
    def __init__(self, salida, explotar=False):
        self.salida = salida
        self.explotar = explotar
        self.matado = self.borrado = False

    def logs(self, **kw):
        if self.explotar:
            raise RuntimeError("fallo a mitad del stream")
        yield from self.salida

    def kill(self):
        self.matado = True

    def wait(self, timeout):
        return {"StatusCode": 0}

    def remove(self, force):
        self.borrado = True


class ClienteFalso:
    def __init__(self, contenedor):
        self.contenedor = contenedor
        self.containers = self

    def info(self):
        return {"Runtimes": {"runc": {}, "runsc": {}}}

    def run(self, **kw):
        self.params = kw
        return self.contenedor

    def get(self, nombre):
        if self.contenedor.borrado:
            raise NotFound("no existe")
        return self.contenedor


def ev(**d) -> bytes:
    return (json.dumps(d) + "\n").encode()


def jpeg_b64() -> str:
    b = io.BytesIO()
    Image.new("RGB", (39, 84), (1, 2, 3)).save(b, format="JPEG")
    return base64.b64encode(b.getvalue()).decode()


def test_ejecutor_salida_gigante_mata_y_borra_el_contenedor(monkeypatch):
    from qrsandbox.orquestador.lector import LectorEventos

    monkeypatch.setattr(ejecutor, "LectorEventos", lambda: LectorEventos(max_total=50_000))
    basura = [ev(tipo="request_tercero", t_ms=1, dominio="ads.cl")] * 10_000
    c = ContenedorFalso(basura)
    r = ejecutor.ejecutar("https://a.cl", ConfigWorker(), ClienteFalso(c))
    assert r.salida_excedida and c.matado and c.borrado
    assert r.contenedor_eliminado


def test_ejecutor_borra_el_contenedor_aunque_falle():
    c = ContenedorFalso([], explotar=True)
    r = ejecutor.ejecutar("https://a.cl", ConfigWorker(), ClienteFalso(c))
    assert r.error and c.borrado and r.contenedor_eliminado


def test_ejecutor_descarta_json_malformado_y_recodifica_capturas(monkeypatch):
    # Sin límite de fps para que el frame falso llegue al re-codificador.
    monkeypatch.setattr(ejecutor, "FiltroEventos", lambda: FiltroEventos(intervalo_captura_s=0))
    salida = [
        b"{basura\n",
        ev(tipo="navegacion", t_ms=1, url="https://a.cl/"),
        ev(tipo="captura", t_ms=2, jpeg_b64=jpeg_b64()),
        ev(tipo="captura", t_ms=3, jpeg_b64=base64.b64encode(b"no es jpeg").decode()),
        ev(tipo="fin", t_ms=4, resultado=None),
    ]
    eventos_vivos = []
    r = ejecutor.ejecutar(
        "https://a.cl", ConfigWorker(), ClienteFalso(ContenedorFalso(salida)), eventos_vivos.append
    )
    assert [e["tipo"] for e in r.eventos] == ["navegacion", "fin"]
    assert r.eventos_descartados == 2  # el JSON roto y el "jpeg" falso
    assert r.frames == 1
    assert base64.b64decode(r.captura_jpeg_b64).startswith(b"\xff\xd8\xff")
    assert [e["tipo"] for e in eventos_vivos] == ["navegacion", "captura", "fin"]
    assert isinstance(eventos_vivos[1]["jpeg"], bytes)


def test_ejecutor_reintenta_con_runc_si_runsc_falla():
    c = ContenedorFalso([ev(tipo="fin", t_ms=1, resultado=None)])

    class ClienteRunscRoto(ClienteFalso):
        def run(self, **kw):
            if kw.get("runtime") == "runsc":
                raise APIError("OCI runtime create failed: runsc: error")
            return super().run(**kw)

    r = ejecutor.ejecutar("https://a.cl", ConfigWorker(perfil="gvisor"), ClienteRunscRoto(c))
    assert r.perfil == "endurecido" and r.runtime == "runc"
    assert r.aviso_runtime and "runsc" in r.aviso_runtime
