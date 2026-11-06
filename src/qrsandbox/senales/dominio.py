"""Utilidades sobre dominios: dominio registrable, homoglifos, sustituciones y marcas.

Todo es offline y determinista (sin red): se puede testear y explicar.
"""

import ipaddress
import json
import os
import unicodedata
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

import tldextract

# Public Suffix List empaquetada con tldextract (sin descargar nada en tiempo de ejecución).
# Con dominios privados: "usuario.github.io" es un dominio registrable distinto de "github.io".
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# Letras de otros alfabetos que se ven idénticas a letras latinas (subconjunto de
# Unicode confusables, los más usados en phishing).
CONFUSABLES = {
    # cirílico
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t",
    "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "ү": "y", "ʐ": "z",
    # griego
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # latín extendido / otros
    "ı": "i", "ɡ": "g", "ɩ": "i", "ɑ": "a", "ʟ": "l", "ꜱ": "s",
}

# Sustituciones ASCII clásicas del typosquatting: (lo que se ve, lo que imita, descripción).
SUSTITUCIONES = [
    ("rn", "m", "«rn» en lugar de «m»"),
    ("vv", "w", "«vv» en lugar de «w»"),
    ("0", "o", "un 0 en lugar de una o"),
    ("1", "l", "un 1 en lugar de una l"),
    ("3", "e", "un 3 en lugar de una e"),
    ("4", "a", "un 4 en lugar de una a"),
    ("5", "s", "un 5 en lugar de una s"),
    ("7", "t", "un 7 en lugar de una t"),
    ("8", "b", "un 8 en lugar de una b"),
]


@dataclass(frozen=True)
class PartesHost:
    host: str  # en ASCII (punycode si es IDN)
    host_unicode: str
    registrable: str  # p. ej. "bancoestado.cl"; vacío para IPs y hosts sin sufijo público
    etiqueta: str  # la parte registrable sin el sufijo: "bancoestado"
    sufijo: str  # "cl", "gob.cl", "co.uk"...
    subdominios: list[str]
    es_ip: bool


def partes_host(url_o_host: str) -> PartesHost:
    host = urlsplit(url_o_host).hostname if "://" in url_o_host else url_o_host
    host = (host or "").lower().rstrip(".")
    if not host.isascii():  # siempre trabajamos con la forma ASCII (punycode)
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    try:
        ipaddress.ip_address(host.strip("[]"))
        return PartesHost(host, host, "", "", "", [], True)
    except ValueError:
        pass
    r = _EXTRACTOR(host)
    registrable = f"{r.domain}.{r.suffix}" if r.domain and r.suffix else ""
    return PartesHost(
        host=host,
        host_unicode=a_unicode(host),
        registrable=registrable,
        etiqueta=r.domain,
        sufijo=r.suffix,
        subdominios=[s for s in r.subdomain.split(".") if s],
        es_ip=False,
    )


def a_unicode(host: str) -> str:
    etiquetas = []
    for e in host.split("."):
        if e.startswith("xn--"):
            try:
                e = e.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        etiquetas.append(e)
    return ".".join(etiquetas)


def alfabetos(texto: str) -> set[str]:
    """Alfabetos de las letras de un texto ("LATIN", "CYRILLIC", "GREEK"...)."""
    salida = set()
    for c in texto:
        if c.isalpha():
            nombre = unicodedata.name(c, "")
            salida.add(nombre.split(" ")[0] if nombre else "DESCONOCIDO")
    return salida


def esqueleto_homoglifos(texto: str) -> str:
    """Reemplaza letras de otros alfabetos por la latina que imitan y quita tildes."""
    t = "".join(CONFUSABLES.get(c, c) for c in texto.lower())
    t = unicodedata.normalize("NFKD", t)
    return "".join(c for c in t if not unicodedata.combining(c))


def deshacer_sustituciones(texto: str) -> tuple[str, list[str]]:
    """Deshace sustituciones tipo 0→o. Devuelve (texto, descripciones aplicadas)."""
    aplicadas = []
    for visto, imitado, descripcion in SUSTITUCIONES:
        if visto in texto:
            texto = texto.replace(visto, imitado)
            aplicadas.append(descripcion)
    return texto, aplicadas


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previa = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        actual = [i]
        for j, cb in enumerate(b, 1):
            actual.append(min(previa[j] + 1, actual[j - 1] + 1, previa[j - 1] + (ca != cb)))
        previa = actual
    return previa[-1]


# ------------------------------------------------------------------ marcas


@dataclass(frozen=True)
class Marca:
    nombre: str
    clave: str
    dominios: tuple[str, ...]
    textos: tuple[str, ...]
    solo_exacta: bool = False

    def es_dominio_legitimo(self, registrable: str) -> bool:
        return registrable in self.dominios or any(
            registrable.endswith("." + d) for d in self.dominios
        )


@cache
def cargar_marcas(ruta: str | None = None) -> tuple[Marca, ...]:
    ruta = ruta or os.environ.get("MARCAS_PATH")
    if ruta:
        texto = Path(ruta).read_text(encoding="utf-8")
    else:
        texto = resources.files("qrsandbox.senales").joinpath("marcas.json").read_text("utf-8")
    datos = json.loads(texto)["marcas"]
    return tuple(
        Marca(m["nombre"], m["clave"], tuple(m["dominios"]), tuple(m.get("textos", [])),
              m.get("solo_exacta", False))
        for m in datos
    )


def dominio_de_alguna_marca(registrable: str, marcas: tuple[Marca, ...]) -> bool:
    return any(m.es_dominio_legitimo(registrable) for m in marcas)
