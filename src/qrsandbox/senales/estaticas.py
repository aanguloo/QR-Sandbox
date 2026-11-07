"""Señales estáticas: lo que se puede decir de una URL SIN abrirla.

Cada `senal_*` es una función pequeña que devuelve 0 o más `Hallazgo`, con su razón en
lenguaje simple. `analizar_url` las combina.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import unquote, urlsplit

from qrsandbox.senales.dominio import (
    Marca,
    PartesHost,
    a_unicode,
    alfabetos,
    cargar_marcas,
    deshacer_sustituciones,
    dominio_de_alguna_marca,
    es_rastreador,
    esqueleto_homoglifos,
    levenshtein,
    motivos_nombre_generado,
    partes_host,
    plataforma_gratuita,
)
from qrsandbox.senales.hallazgos import Hallazgo
from qrsandbox.senales.listas import ListasNegras
from qrsandbox.senales.red import InfoCertificado, ProveedorRed

# TLDs baratos o gratuitos, sobrerrepresentados en reportes de abuso (Spamhaus, Interisle).
TLDS_RIESGOSOS = {
    "xyz", "top", "click", "link", "buzz", "rest", "live", "icu", "cyou", "cfd", "sbs", "zip",
    "mov", "tk", "ml", "ga", "cf", "gq", "work", "support", "online", "site", "store", "shop",
    "monster", "quest", "lol", "bond", "beauty", "hair", "skin", "makeup", "autos", "boats",
    "pics", "fun", "space", "website", "club", "win", "loan", "country", "kim", "date", "cam",
}
ACORTADORES = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "v.gd",
    "qrco.de", "l.ead.me", "u.to", "shorturl.com", "short.io", "lnkd.in", "bl.ink", "tny.im",
    "me-qr.com", "qr.me-qr.com", "qrcode-monkey.com", "qr-codes.io", "linktr.ee",
}
PALABRAS_CLAVE = {
    "login", "signin", "sign-in", "logon", "verify", "verificar", "verificacion", "secure",
    "seguro", "account", "cuenta", "update", "actualizar", "confirm", "confirmar", "banking",
    "clave", "password", "contrasena", "validar", "desbloquear", "suspendido", "suspended",
    "recuperar", "webscr", "wallet", "billing", "facturacion", "reembolso", "premio",
}


@dataclass
class ResultadoEstatico:
    url: str
    partes: PartesHost
    hallazgos: list[Hallazgo] = field(default_factory=list)
    datos: dict = field(default_factory=dict)


# ---------------------------------------------------------------- forma de la URL


def senal_esquema(url: str) -> list[Hallazgo]:
    if urlsplit(url).scheme == "http":
        return [Hallazgo("sin_https", "La conexión no está cifrada (http, sin «s»): "
                         "cualquiera en la red puede ver o cambiar lo que envíes.",
                         "no usa conexión cifrada")]
    return []


def senal_userinfo(url: str) -> list[Hallazgo]:
    netloc = urlsplit(url).netloc
    if "@" in netloc:
        antes, despues = netloc.rsplit("@", 1)
        return [Hallazgo("userinfo_arroba", f"La URL contiene «@»: todo lo anterior («{antes[:40]}») "
                         f"se ignora y el sitio real es «{despues}».",
                         "esconde el sitio real detrás de un «@»")]
    return []


def senal_ip(p: PartesHost) -> list[Hallazgo]:
    if p.es_ip:
        return [Hallazgo("ip_literal", f"Apunta a una dirección IP ({p.host}) en vez de a un "
                         "nombre de dominio: los sitios legítimos casi nunca hacen esto.",
                         "usa una dirección IP en vez de un dominio")]
    return []


def senal_puerto(url: str) -> list[Hallazgo]:
    try:
        puerto = urlsplit(url).port
    except ValueError:
        return []
    if puerto and puerto not in (80, 443):
        return [Hallazgo("puerto_no_estandar", f"Usa un puerto poco común ({puerto}).",
                         f"usa el puerto poco común {puerto}")]
    return []


def senal_tld(p: PartesHost) -> list[Hallazgo]:
    tld = p.sufijo.rsplit(".", 1)[-1]
    if tld in TLDS_RIESGOSOS:
        return [Hallazgo("tld_riesgoso", f"Termina en «.{tld}», una terminación barata muy "
                         "usada en sitios de phishing.", f"usa la terminación «.{tld}»")]
    return []


def senal_acortador(p: PartesHost) -> list[Hallazgo]:
    if p.host in ACORTADORES or p.registrable in ACORTADORES:
        return [Hallazgo("acortador", f"Es un enlace acortado ({p.host}): esconde el destino "
                         "real hasta que se abre.", "es un enlace acortado que esconde el destino")]
    return []


def senal_hosting_gratuito(p: PartesHost) -> list[Hallazgo]:
    """Página en un hosting gratuito y, sobre todo, con un nombre generado al azar."""
    encontrado = plataforma_gratuita(p)
    if not encontrado:
        return []
    plataforma, nombre = encontrado
    h = [Hallazgo("hosting_gratuito", f"El sitio está en {plataforma}, un servicio donde cualquiera "
                  "publica una página gratis en minutos: el candado y la antigüedad del dominio son "
                  "de la plataforma, no de este sitio.", f"está en un hosting gratuito ({plataforma})")]
    if motivos := motivos_nombre_generado(nombre):
        h.append(Hallazgo("nombre_generado", f"El nombre «{nombre}» parece generado automáticamente "
                          f"({', '.join(motivos)}), algo típico de páginas desechables.",
                          "usa un nombre generado al azar"))
    return h


def senal_subdominios(p: PartesHost) -> list[Hallazgo]:
    subs = [s for s in p.subdominios if s != "www"]
    if len(subs) >= 4:
        return [Hallazgo("muchos_subdominios", f"Tiene muchos subdominios ({len(subs)}), un truco "
                         "para que el comienzo de la dirección parezca otro sitio.",
                         "tiene una cadena larga de subdominios")]
    return []


def senal_palabras_clave(url: str) -> list[Hallazgo]:
    partes = urlsplit(url)
    texto = unquote(f"{partes.hostname} {partes.path} {partes.query}").lower()
    for separador in "./-_?=&":
        texto = texto.replace(separador, " ")
    encontradas = sorted(PALABRAS_CLAVE & set(texto.split()))
    if encontradas:
        return [Hallazgo("palabras_clave", f"La dirección usa palabras típicas de phishing: "
                         f"{', '.join(encontradas[:4])}.", "usa palabras como «"
                         + encontradas[0] + "» en la dirección")]
    return []


def hallazgo_rastreador(host: str) -> Hallazgo:
    return Hallazgo(
        "rastreador_ip",
        f"El enlace pasa por {host}, un servicio que registra la IP (y con ella la ubicación "
        "aproximada), el navegador y el teléfono de quien lo abre, antes de redirigir.",
        "pasa por un servicio que registra tu IP y ubicación aproximada")


def senal_rastreador(p: PartesHost) -> list[Hallazgo]:
    return [hallazgo_rastreador(p.host)] if es_rastreador(p) else []


# ---------------------------------------------------------------- marcas y homoglifos


# Señales de marca que se omiten en sitios populares (top de Tranco): son las que más
# falsos positivos dan. Homoglifos y sustituciones (0→o) se mantienen siempre: son engaño
# deliberado (p. ej. "googll.store" está en el top 5.000 de Tranco).
DEBILES_EN_POPULARES = {"typosquatting_marca", "marca_en_dominio_ajeno"}


def senal_marca(
    p: PartesHost, marcas: tuple[Marca, ...], popular: bool = False
) -> list[Hallazgo]:
    """Suplantación de marca en el dominio. Devuelve a lo más UN hallazgo (el más fuerte).

    `popular`: el dominio está en el top de Tranco (se omiten las señales débiles).
    """
    if p.es_ip or not p.registrable or dominio_de_alguna_marca(p.registrable, marcas):
        return []
    etiqueta_u = a_unicode(p.etiqueta)
    esqueleto = esqueleto_homoglifos(etiqueta_u).replace("-", "")
    sin_sust, sustituciones = deshacer_sustituciones(esqueleto)
    etiquetas = [*p.subdominios, p.etiqueta]
    candidatos: list[Hallazgo] = []
    for m in marcas:
        clave = m.clave
        imita = esqueleto == clave or (not m.solo_exacta and clave in esqueleto)
        if p.etiqueta.startswith("xn--") and imita and p.etiqueta.replace("-", "") != clave:
            candidatos.append(Hallazgo(
                "homoglifos_marca",
                f"«{p.host_unicode}» imita a {m.nombre} usando letras de otro alfabeto: se ve "
                f"igual, pero en realidad es el dominio «{p.host}».",
                f"imita a {m.nombre} con letras de otro alfabeto"))
            continue
        imita_sust = sin_sust == clave or (
            not m.solo_exacta and clave in sin_sust and clave not in esqueleto)
        if sustituciones and imita_sust:
            candidatos.append(Hallazgo(
                "sustitucion_marca",
                f"«{p.registrable}» imita a {m.nombre}: usa {', '.join(sustituciones)}.",
                f"usa {sustituciones[0]} para imitar a {m.nombre}"))
            continue
        umbral = 0 if len(clave) <= 4 else 1 if len(clave) <= 6 else 2
        distancia = levenshtein(esqueleto, clave)
        if 0 < distancia <= umbral:
            letras = "letra" if distancia == 1 else "letras"
            candidatos.append(Hallazgo(
                "typosquatting_marca",
                f"«{p.registrable}» se parece mucho a {m.nombre} ({distancia} {letras} de "
                f"diferencia), pero no es un dominio de {m.nombre}.",
                f"se parece a {m.nombre} pero cambia {distancia} {letras}"))
            continue
        for e in etiquetas:
            tokens = esqueleto_homoglifos(a_unicode(e)).split("-")
            junto = "".join(tokens)
            if clave in tokens or (not m.solo_exacta and clave in junto):
                candidatos.append(Hallazgo(
                    "marca_en_dominio_ajeno",
                    f"La dirección contiene «{clave}», pero «{p.registrable}» no pertenece a "
                    f"{m.nombre}.",
                    f"usa el nombre de {m.nombre} en un dominio que no es suyo"))
                break
    if popular:
        candidatos = [c for c in candidatos if c.codigo not in DEBILES_EN_POPULARES]
    return [max(candidatos, key=lambda h: h.peso)] if candidatos else []


def senal_punycode(p: PartesHost) -> list[Hallazgo]:
    if any(e.startswith("xn--") for e in p.host.split(".")):
        mezcla = len(alfabetos(p.host_unicode.replace(".", ""))) > 1
        detalle = " y mezcla alfabetos distintos" if mezcla else ""
        return [Hallazgo("punycode", f"El dominio usa caracteres internacionales («{p.host_unicode}» "
                         f"= «{p.host}»){detalle}.", "usa caracteres internacionales en el dominio")]
    return []


# ---------------------------------------------------------------- listas y red


def senal_lista_negra(url: str, listas: ListasNegras | None) -> list[Hallazgo]:
    if listas is None:
        return []
    tipo = listas.consultar(url)
    if tipo == "url":
        return [Hallazgo("lista_negra_url", "Esta dirección exacta aparece en listas públicas de "
                         "phishing/malware.", "aparece en listas públicas de phishing")]
    if tipo == "dominio":
        return [Hallazgo("lista_negra_dominio", "El sitio tiene otras direcciones reportadas en "
                         "listas públicas de phishing/malware.", "su sitio tiene reportes de phishing")]
    return []


def _hace(dias: int) -> str:
    return "hoy" if dias == 0 else "ayer" if dias == 1 else f"hace {dias} días"


def senal_edad_dominio(dias: int | None) -> list[Hallazgo]:
    if dias is None:
        return []
    if dias < 7:
        return [Hallazgo("dominio_muy_nuevo", f"El dominio se registró {_hace(dias)}: los sitios "
                         "de phishing suelen vivir pocos días.", f"el dominio se creó {_hace(dias)}")]
    if dias < 30:
        return [Hallazgo("dominio_nuevo", f"El dominio es reciente (registrado {_hace(dias)}).",
                         f"el dominio tiene solo {dias} días")]
    return []


def senal_certificado(info: InfoCertificado | None, ahora: datetime | None = None) -> list[Hallazgo]:
    if info is None:
        return []
    ahora = ahora or datetime.now(UTC)
    if not info.valido:
        return [Hallazgo("certificado_invalido", f"El certificado de seguridad no es válido "
                         f"({info.error}).", "su certificado de seguridad no es válido")]
    dias = (ahora - info.emitido).days
    if 0 <= dias < 7:
        return [Hallazgo("certificado_reciente", f"El certificado se emitió {_hace(dias)} "
                         f"({info.emisor}).", f"el certificado se emitió {_hace(dias)}")]
    return []


# ---------------------------------------------------------------- combinación


def analizar_url(
    url: str,
    *,
    marcas: tuple[Marca, ...] | None = None,
    listas: ListasNegras | None = None,
    red: ProveedorRed | None = None,
) -> ResultadoEstatico:
    marcas = marcas if marcas is not None else cargar_marcas()
    p = partes_host(url)
    r = ResultadoEstatico(url=url, partes=p)
    h = r.hallazgos
    h += senal_lista_negra(url, listas)
    h += senal_userinfo(url) + senal_ip(p) + senal_esquema(url) + senal_puerto(url)
    popular = bool(listas and p.registrable and listas.es_popular(p.registrable))
    marca = senal_marca(p, marcas, popular)
    h += marca
    if not any(x.codigo == "homoglifos_marca" for x in marca):
        h += senal_punycode(p)
    h += senal_rastreador(p) + senal_hosting_gratuito(p) + senal_tld(p) + senal_acortador(p) + senal_subdominios(p) + senal_palabras_clave(url)
    r.datos = {"host": p.host, "host_unicode": p.host_unicode, "dominio": p.registrable,
               "lista_negra_cargada": listas is not None and not listas.vacia,
               "rango_tranco": listas.popularidad(p.registrable) if listas and p.registrable else None}
    if red is not None and not p.es_ip:
        dias = red.edad_dominio_dias(p.registrable)
        cert = red.certificado(p.host) if urlsplit(url).scheme == "https" else None
        r.datos["edad_dominio_dias"] = dias
        if cert:
            r.datos["certificado"] = {
                "valido": cert.valido, "emisor": cert.emisor,
                "emitido": cert.emitido.isoformat(), "expira": cert.expira.isoformat(),
            }
        h += senal_edad_dominio(dias) + senal_certificado(cert)
    return r
