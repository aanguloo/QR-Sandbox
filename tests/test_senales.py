"""Fase 4 (aceptación): un test por señal estática y dinámica (sin red)."""

from datetime import UTC, datetime, timedelta

import pytest

from qrsandbox.comun.esquemas import ResultadoAnalisis, ResultadoWorker
from qrsandbox.senales import estaticas as E
from qrsandbox.senales.dinamicas import marcas_mencionadas, senales_dinamicas
from qrsandbox.senales.dominio import (
    cargar_marcas,
    deshacer_sustituciones,
    esqueleto_homoglifos,
    levenshtein,
    partes_host,
)
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.senales.red import InfoCertificado, ProveedorRedReal

MARCAS = cargar_marcas()


def codigos(hallazgos) -> set[str]:
    return {h.codigo for h in hallazgos}


def marca(url):
    return E.senal_marca(partes_host(url), MARCAS)


# ------------------------------------------------------------------ utilidades


def test_partes_host_usa_la_public_suffix_list():
    p = partes_host("https://login.sii.gob.cl/x")
    assert (p.registrable, p.etiqueta, p.sufijo, p.subdominios) == ("sii.gob.cl", "sii", "gob.cl", ["login"])
    assert partes_host("https://usuario.github.io").registrable == "usuario.github.io"
    assert partes_host("http://10.0.0.1/").es_ip


def test_esqueleto_y_sustituciones():
    assert esqueleto_homoglifos("bancoestаdo") == "bancoestado"  # "а" cirílica
    assert esqueleto_homoglifos("pаypаl") == "paypal"
    assert deshacer_sustituciones("micr0soft") == ("microsoft", ["un 0 en lugar de una o"])
    assert deshacer_sustituciones("rnicrosoft")[0] == "microsoft"
    assert levenshtein("bancoestado", "bancoestaod") == 2
    assert levenshtein("santander", "santander") == 0


# ------------------------------------------------------------------ forma de la URL


def test_senal_esquema():
    assert codigos(E.senal_esquema("http://a.cl/")) == {"sin_https"}
    assert E.senal_esquema("https://a.cl/") == []


def test_senal_userinfo():
    h = E.senal_userinfo("https://www.bancoestado.cl@malo.xyz/login")
    assert codigos(h) == {"userinfo_arroba"} and "malo.xyz" in h[0].razon
    assert E.senal_userinfo("https://a.cl/x@y") == []  # @ en la ruta no engaña


def test_senal_ip():
    assert codigos(E.senal_ip(partes_host("http://45.33.12.9/login"))) == {"ip_literal"}
    assert E.senal_ip(partes_host("https://a.cl")) == []


def test_senal_puerto():
    assert codigos(E.senal_puerto("https://a.cl:8443/")) == {"puerto_no_estandar"}
    assert E.senal_puerto("https://a.cl:443/") == []


def test_senal_tld():
    assert codigos(E.senal_tld(partes_host("https://pago-seguro.xyz"))) == {"tld_riesgoso"}
    assert E.senal_tld(partes_host("https://pago.cl")) == []


def test_senal_acortador():
    assert codigos(E.senal_acortador(partes_host("https://bit.ly/3abc"))) == {"acortador"}
    assert E.senal_acortador(partes_host("https://bitlyx.cl")) == []


def test_senal_subdominios():
    p = partes_host("https://www.bancoestado.cl.cuenta.segura.verificar.malo.com")
    assert codigos(E.senal_subdominios(p)) == {"muchos_subdominios"}
    assert E.senal_subdominios(partes_host("https://www.a.b.cl")) == []


def test_senal_palabras_clave():
    h = E.senal_palabras_clave("https://x.cl/cuenta/verificar?login=1")
    assert codigos(h) == {"palabras_clave"} and "verificar" in h[0].razon
    assert E.senal_palabras_clave("https://restaurante.cl/menu") == []


# ------------------------------------------------------------------ marcas


def test_homoglifos_imitan_marca():
    h = marca("https://bancoestаdo.cl/")  # "а" cirílica -> normalizada a xn--
    assert codigos(h) == {"homoglifos_marca"}
    assert "BancoEstado" in h[0].razon and "xn--" in h[0].razon


def test_sustitucion_de_caracteres():
    h = marca("https://login-micr0soft.xyz/")
    assert codigos(h) == {"sustitucion_marca"}
    assert "un 0 en lugar de una o" in h[0].frase and "Microsoft" in h[0].frase
    assert codigos(marca("https://paypa1.com/")) == {"sustitucion_marca"}


def test_typosquatting():
    assert codigos(marca("https://bancoestaod.cl/")) == {"typosquatting_marca"}
    assert codigos(marca("https://santnader.cl/")) == {"typosquatting_marca"}
    assert marca("https://bci2.cl/") == []  # marcas cortas: sin distancia de edición


def test_marca_en_dominio_ajeno():
    h = marca("https://bancoestado.cl-seguridad.com/")
    assert codigos(h) == {"marca_en_dominio_ajeno"}
    assert codigos(marca("https://bci.verifica-cuenta.top/")) == {"marca_en_dominio_ajeno"}
    assert marca("https://bcientifica.cl/") == []  # "bci" corto: solo coincidencia exacta


@pytest.mark.parametrize("url", [
    "https://www.bancoestado.cl/", "https://login.microsoftonline.com/", "https://accounts.google.com/",
    "https://www.sii.gob.cl/", "https://storage.googleapis.com/x", "https://restaurante-la-esquina.cl/",
])
def test_dominios_legitimos_o_neutros_no_disparan_marca(url):
    assert marca(url) == []


def test_senal_punycode_sin_marca():
    p = partes_host("https://xn--caf-dma.cl/")  # café.cl
    assert codigos(E.senal_punycode(p)) == {"punycode"}
    assert E.senal_punycode(partes_host("https://cafe.cl/")) == []


# ------------------------------------------------------------------ listas negras


def test_lista_negra(tmp_path):
    (tmp_path / "openphish.txt").write_text("# snapshot\nhttps://malo.xyz/login\nhttps://sites.google.com/view/phish\n")
    listas = ListasNegras.desde_directorio(tmp_path)
    assert listas.fuentes == {"openphish": 2}
    assert codigos(E.senal_lista_negra("https://MALO.xyz/login", listas)) == {"lista_negra_url"}
    assert codigos(E.senal_lista_negra("https://malo.xyz/otra", listas)) == {"lista_negra_dominio"}
    # Plataforma compartida: otra página del mismo host NO se marca.
    assert E.senal_lista_negra("https://sites.google.com/view/otra", listas) == []
    assert E.senal_lista_negra("https://bueno.cl/", listas) == []
    assert ListasNegras.desde_directorio(tmp_path / "no-existe").vacia


# ------------------------------------------------------------------ red (simulada)


def test_senal_edad_dominio():
    assert codigos(E.senal_edad_dominio(2)) == {"dominio_muy_nuevo"}
    assert "hace 2 días" in E.senal_edad_dominio(2)[0].frase
    assert codigos(E.senal_edad_dominio(20)) == {"dominio_nuevo"}
    assert E.senal_edad_dominio(400) == [] and E.senal_edad_dominio(None) == []


def test_senal_certificado():
    ahora = datetime(2026, 11, 6, tzinfo=UTC)
    nuevo = InfoCertificado(True, "Let's Encrypt", ahora - timedelta(days=1), ahora + timedelta(days=89))
    viejo = InfoCertificado(True, "DigiCert", ahora - timedelta(days=200), ahora + timedelta(days=100))
    malo = InfoCertificado(False, "x", ahora, ahora, "self-signed certificate")
    assert "ayer" in E.senal_certificado(nuevo, ahora)[0].frase
    assert E.senal_certificado(viejo, ahora) == []
    assert codigos(E.senal_certificado(malo, ahora)) == {"certificado_invalido"}


def test_tls_no_se_conecta_a_ips_internas():
    """El handshake TLS desde la API aplica la política anti-SSRF del proxy."""
    def resolver(ip):
        return lambda host, puerto, type=None: [(2, 1, 6, "", (ip, puerto))]

    for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1"):
        red = ProveedorRedReal(resolver=resolver(ip))
        assert red.ip_validada("rebind.example") is None
        assert red.certificado("rebind.example") is None  # ni siquiera intenta conectar
    assert ProveedorRedReal(resolver=resolver("93.184.215.14")).ip_validada("x") == "93.184.215.14"


class RedFalsa:
    def __init__(self, dias=None, cert=None):
        self.dias, self.cert = dias, cert

    def edad_dominio_dias(self, registrable):
        return self.dias

    def certificado(self, host):
        return self.cert


def test_analizar_url_combina_y_usa_la_red():
    ahora = datetime.now(UTC)
    cert = InfoCertificado(True, "Let's Encrypt", ahora - timedelta(hours=20), ahora + timedelta(days=89))
    r = E.analizar_url("https://login-micr0soft.xyz/verify", red=RedFalsa(2, cert))
    assert codigos(r.hallazgos) == {
        "sustitucion_marca", "tld_riesgoso", "palabras_clave", "dominio_muy_nuevo", "certificado_reciente",
    }
    assert r.datos["edad_dominio_dias"] == 2 and r.datos["certificado"]["valido"]
    limpio = E.analizar_url("https://www.bancoestado.cl/", red=RedFalsa(9000, None))
    assert limpio.hallazgos == []


# ------------------------------------------------------------------ dinámicas


def analisis(**resultado) -> ResultadoAnalisis:
    base = {
        "url_inicial": "https://bit.ly/x", "url_final": "https://login-micr0soft.xyz/",
        "cadena_redirecciones": ["https://bit.ly/x", "https://a.cl/", "https://b.cl/", "https://login-micr0soft.xyz/"],
        "titulo": "Sign in to your Microsoft account", "estado_http": 200,
        "formularios_password": 1, "dominios_terceros": [], "n_dominios_terceros": 3,
        "tiempo_carga_ms": 900, "texto_visible": "",
    }
    base.update(resultado)
    eventos = base.pop("_eventos", [])
    return ResultadoAnalisis(
        id="0" * 12, url=base["url_inicial"], runtime="runsc", duracion_ms=1, codigo_salida=0,
        timeout=False, salida_excedida=False, eventos=eventos, eventos_descartados=0,
        resultado=ResultadoWorker.model_validate(base), captura_jpeg_b64=None, contenedor_eliminado=True,
    )


def test_dinamicas_phishing_con_marca_y_password():
    h = senales_dinamicas(analisis())
    assert codigos(h) == {"muchas_redirecciones", "cambio_de_dominio", "marca_en_pagina_ajena", "password_con_marca_ajena"}


def test_dinamicas_login_legitimo_no_alerta_por_marca():
    h = senales_dinamicas(analisis(
        url_inicial="https://login.microsoftonline.com/", url_final="https://login.microsoftonline.com/",
        cadena_redirecciones=["https://login.microsoftonline.com/"]))
    assert codigos(h) == {"formulario_password"}  # pide clave, pero en su propio dominio


def test_marca_en_texto_solo_cuenta_con_password():
    sin_pw = analisis(titulo="Recetas", texto_visible="Inicia sesión con Google", formularios_password=0,
                      cadena_redirecciones=["https://bit.ly/x"], url_final="https://bit.ly/x")
    assert "marca_en_pagina_ajena" not in codigos(senales_dinamicas(sin_pw))
    con_pw = analisis(titulo="Recetas", texto_visible="Ingresa tu clave de BancoEstado")
    assert "marca_en_pagina_ajena" in codigos(senales_dinamicas(con_pw))


def test_titulo_hostil_no_rompe_la_busqueda_de_marcas():
    titulo = "<script>alert(1)</script> (.*)+$ " * 8
    assert marcas_mencionadas(titulo, MARCAS) == []


def test_dinamicas_descarga_y_terceros():
    h = senales_dinamicas(analisis(
        titulo="x", formularios_password=0, n_dominios_terceros=40,
        cadena_redirecciones=["https://bit.ly/x"], url_final="https://bit.ly/x",
        _eventos=[{"tipo": "descarga_bloqueada", "t_ms": 1, "url": "https://bit.ly/f.apk", "nombre": "app.apk"}]))
    assert codigos(h) == {"descarga", "muchos_terceros"}


def test_dinamicas_sin_resultado():
    assert senales_dinamicas(None) == []
