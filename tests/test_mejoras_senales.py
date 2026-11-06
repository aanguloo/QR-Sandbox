"""Mejoras previas a la Fase 5: snapshots con fecha, Tranco, whois .cl y pistas de logos."""

import sqlite3

import pytest

from qrsandbox.senales import estaticas as E
from qrsandbox.senales.dinamicas import marcas_en_imagenes, senales_dinamicas
from qrsandbox.senales.dominio import cargar_marcas, partes_host
from qrsandbox.senales.listas import ListasNegras, construir_indice
from qrsandbox.senales.red import ProveedorRedReal, fecha_creacion_whois

from .test_senales import analisis, codigos

MARCAS = cargar_marcas()


@pytest.fixture
def directorio(tmp_path):
    s = tmp_path / "snapshots"
    s.mkdir()
    (s / "urls-openphish-2026-11-05.txt").write_text("# viejo\nhttps://ayer.xyz/login\n")
    (s / "urls-openphish-2026-11-06.txt").write_text("https://hoy.xyz/login\n")
    (s / "dominios-phishingdb-2026-11-05.txt").write_text("dominio-viejo.com\n")
    (s / "dominios-phishingdb-2026-11-06.txt").write_text("estafa.com\ngravatar.com\n")
    (s / "tranco-2026-11-06.csv").write_text("1,google.com\n167,gravatar.com\n4258,googll.store\n")
    return tmp_path


def test_snapshots_de_urls_se_acumulan_y_los_de_dominios_no(directorio):
    listas = ListasNegras.desde_directorio(directorio)
    assert listas.consultar("https://ayer.xyz/login") == "url"  # snapshot de ayer
    assert listas.consultar("https://hoy.xyz/login") == "url"
    assert listas.consultar("https://estafa.com/x") == "dominio"
    assert listas.consultar("https://dominio-viejo.com/") is None  # solo el último
    assert listas.fuentes == {"openphish": 2, "phishingdb": 2, "tranco": 3}


def test_sitio_popular_no_se_marca_por_dominio(directorio):
    """Phishing.Database incluye gravatar.com (puesto 167): no se marca por dominio."""
    listas = ListasNegras.desde_directorio(directorio)
    assert listas.consultar("https://gravatar.com/avatar") is None
    assert listas.popularidad("gravatar.com") == 167 and listas.es_popular("gravatar.com")
    assert listas.popularidad("estafa.com") is None


def test_url_exacta_cuenta_aunque_el_sitio_sea_popular(directorio):
    (directorio / "snapshots" / "urls-manual-2026-11-06.txt").write_text("https://gravatar.com/phish\n")
    listas = ListasNegras.desde_directorio(directorio)
    assert listas.consultar("https://gravatar.com/phish") == "url"  # sitio popular comprometido


def test_indice_sqlite_se_abre_en_solo_lectura(directorio):
    construir_indice(directorio, directorio / "listas.sqlite")
    listas = ListasNegras.desde_directorio(directorio)
    assert listas.consultar("https://hoy.xyz/login") == "url"
    with pytest.raises(sqlite3.OperationalError):
        listas._con.execute("INSERT INTO urls VALUES ('x', 'y', 'z')")


def test_popular_omite_solo_las_senales_debiles_de_marca():
    # typosquatting: se omite si el dominio es popular...
    p = partes_host("https://bancoestaod.cl/")
    assert codigos(E.senal_marca(p, MARCAS, popular=False)) == {"typosquatting_marca"}
    assert E.senal_marca(p, MARCAS, popular=True) == []
    # ...pero una sustitución deliberada (0 por o) se mantiene siempre.
    p = partes_host("https://micr0soft.com/")
    assert codigos(E.senal_marca(p, MARCAS, popular=True)) == {"sustitucion_marca"}


def test_analizar_url_informa_rango_tranco(directorio):
    listas = ListasNegras.desde_directorio(directorio)
    assert E.analizar_url("https://www.google.com/", listas=listas).datos["rango_tranco"] == 1


# ------------------------------------------------------------------ whois .cl


def test_fecha_creacion_whois():
    texto = "Registrant name: Banco\nCreation date: 1999-08-30 20:41:44 CLST\nExpiration date: 2031"
    assert fecha_creacion_whois(texto).year == 1999
    assert fecha_creacion_whois("sin datos") is None


@pytest.mark.parametrize("malo", ["x\r\nbancoestado.cl", "bancoestado.cl\n", "a b.cl", "-x.cl", "ñandú.cl"])
def test_whois_rechaza_dominios_con_caracteres_peligrosos(malo):
    """El dominio va a una consulta de texto plano: nada de saltos de línea ni espacios."""
    assert ProveedorRedReal().edad_dominio_dias(malo) is None  # no llega a conectarse


# ------------------------------------------------------------------ pistas de logos


def test_marcas_en_imagenes():
    encontradas = marcas_en_imagenes(["archivo:microsoft_logo.svg", "alt:Logo BancoEstado",
                                      "archivo:IMG_2034.jpg"], MARCAS)
    assert {m.clave for m, _ in encontradas} == {"microsoft", "bancoestado"}
    assert marcas_en_imagenes(["archivo:bcientifica.png"], MARCAS) == []  # "bci" solo exacta


def test_logo_con_password_en_dominio_ajeno():
    a = analisis(titulo="Iniciar sesión", texto_visible="", imagenes=["archivo:microsoft_logo.svg"])
    h = {x.codigo: x for x in senales_dinamicas(a)}
    assert "marca_en_pagina_ajena" in h
    assert "logo de Microsoft" in h["marca_en_pagina_ajena"].frase
    assert "microsoft_logo.svg" in h["marca_en_pagina_ajena"].razon


def test_iconos_sociales_sin_password_no_alertan():
    a = analisis(titulo="Restaurante", formularios_password=0, url_final="https://bit.ly/x",
                 cadena_redirecciones=["https://bit.ly/x"],
                 imagenes=["archivo:facebook.svg", "archivo:google-play-badge.png", "alt:Instagram"])
    assert "marca_en_pagina_ajena" not in codigos(senales_dinamicas(a))


# ------------------------------------------------------------------ con red real


@pytest.mark.integracion
def test_whois_nic_chile_real():
    dias = ProveedorRedReal().edad_dominio_dias("bancoestado.cl")
    assert dias is not None and dias > 9000  # creado en 1999


# ------------------------------------------------------------------ falsos positivos reales


def test_login_social_no_es_suplantacion():
    """Caso real (github.com/login): contraseña + "Continue with Google" daba peligroso 75."""
    a = analisis(url_inicial="https://login-ejemplo.dev/", url_final="https://login-ejemplo.dev/",
                 cadena_redirecciones=["https://login-ejemplo.dev/"], titulo="Sign in",
                 texto_visible="Username Password Sign in or Continue with Google / Iniciar con Apple ID")
    assert codigos(senales_dinamicas(a)) == {"formulario_password"}


def test_pero_ingresar_clave_de_la_marca_si_alerta():
    a = analisis(titulo="Acceso", texto_visible="Ingresa tu RUT y la clave de tu cuenta BancoEstado")
    assert "marca_en_pagina_ajena" in codigos(senales_dinamicas(a))


def test_sitio_popular_no_dispara_marca_en_pagina(directorio):
    listas = ListasNegras.desde_directorio(directorio)
    a = analisis(url_inicial="https://google.com/", url_final="https://google.com/",
                 cadena_redirecciones=["https://google.com/"], titulo="Microsoft account sign in")
    assert "marca_en_pagina_ajena" not in codigos(senales_dinamicas(a, es_popular=listas.es_popular))
    assert "marca_en_pagina_ajena" in codigos(senales_dinamicas(a))
