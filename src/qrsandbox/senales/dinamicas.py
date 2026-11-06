"""Señales dinámicas: lo que el sandbox observó al cargar la página.

Los datos vienen del worker (tainted) pero ya pasaron el esquema estricto. El título y el
texto visible son ENTRADA DEL ATACANTE: aquí solo se buscan nombres de marca con
expresiones regulares acotadas; nunca se ejecutan ni se insertan como HTML.
"""

import re

from qrsandbox.comun.esquemas import ResultadoAnalisis
from qrsandbox.senales.dominio import Marca, cargar_marcas, es_rastreador, partes_host
from qrsandbox.senales.estaticas import hallazgo_rastreador
from qrsandbox.senales.hallazgos import Hallazgo

# "Continuar con Google", "Sign in with Apple"...: botones de inicio de sesión social, muy
# comunes en sitios legítimos. Una mención así NO es suplantación.
_SOCIAL = re.compile(r"(?:\bwith|\bcon|\busing|\bvia|\bmediante)\s+$", re.IGNORECASE)


def marcas_mencionadas(
    texto: str, marcas: tuple[Marca, ...], ignorar_social: bool = False
) -> list[Marca]:
    encontradas = []
    for m in marcas:
        for t in m.textos:
            patron = r"(?<!\w)" + re.escape(t) + r"(?!\w)"
            for coincidencia in re.finditer(patron, texto, re.IGNORECASE):
                antes = texto[max(0, coincidencia.start() - 12) : coincidencia.start()]
                if ignorar_social and _SOCIAL.search(antes):
                    continue
                encontradas.append(m)
                break
            if encontradas and encontradas[-1] is m:
                break
    return encontradas


def marcas_en_imagenes(imagenes: list[str], marcas: tuple[Marca, ...]) -> list[tuple[Marca, str]]:
    """Marcas sugeridas por el texto alternativo o el nombre de archivo de una imagen."""
    encontradas: list[tuple[Marca, str]] = []
    for entrada in imagenes:
        tipo, _, valor = entrada.partition(":")
        if tipo == "alt":
            for m in marcas_mencionadas(valor, marcas):
                encontradas.append((m, valor))
            continue
        tokens = [t for t in re.split(r"[^a-z0-9]+", valor.lower()) if t]
        junto = "".join(tokens)
        for m in marcas:
            if m.clave in tokens or (not m.solo_exacta and m.clave in junto):
                encontradas.append((m, valor))
    return encontradas


def senales_dinamicas(
    analisis: ResultadoAnalisis | None,
    marcas: tuple[Marca, ...] | None = None,
    es_popular=None,
) -> list[Hallazgo]:
    """`es_popular(dominio) -> bool` (Tranco): en sitios populares no se aplica la señal
    de marca en la página (evita falsos positivos en noticias o logins legítimos; a cambio
    no detecta phishing alojado en un sitio popular comprometido)."""
    if analisis is None or analisis.resultado is None:
        return []
    marcas = marcas if marcas is not None else cargar_marcas()
    r = analisis.resultado
    h: list[Hallazgo] = []

    saltos = max(0, len(r.cadena_redirecciones) - 1)
    if saltos >= 3:
        h.append(Hallazgo("muchas_redirecciones", f"Pasa por {saltos} redirecciones antes de "
                          "llegar al destino.", f"pasa por {saltos} redirecciones"))

    # Un IP logger suele esconderse detrás de un acortador: se revisa cada salto.
    for salto in r.cadena_redirecciones:
        p = partes_host(salto)
        if es_rastreador(p):
            h.append(hallazgo_rastreador(p.host))
            break

    inicial = partes_host(r.url_inicial)
    final = partes_host(r.url_final) if r.url_final else inicial
    if r.url_final and final.registrable != inicial.registrable and final.host != inicial.host:
        h.append(Hallazgo("cambio_de_dominio", f"Empieza en «{inicial.host}» pero termina en "
                          f"«{final.host}».", f"termina en otro dominio ({final.host})"))

    # Marca en la página de un dominio que no es suyo. El título cuenta solo. El texto
    # visible y las imágenes (alt / nombre de archivo, aproximación a "muestra el logo")
    # solo si además pide contraseña: muchas páginas legítimas dicen "Google" o tienen
    # íconos de Facebook o insignias de Google Play en el pie.
    def ajena(m: Marca) -> bool:
        return not m.es_dominio_legitimo(final.registrable)

    dominio = final.registrable or final.host
    popular = bool(es_popular and final.registrable and es_popular(final.registrable))
    marca, razon, frase = None, "", ""
    if popular:
        pass
    elif en_titulo := [m for m in marcas_mencionadas(r.titulo, marcas, True) if ajena(m)]:
        marca = en_titulo[0]
        razon = f"La página se presenta como {marca.nombre} en el título"
        frase = f"muestra la marca {marca.nombre} en un dominio que no es de {marca.nombre}"
    elif r.formularios_password:
        en_texto = [m for m in marcas_mencionadas(r.texto_visible, marcas, True) if ajena(m)]
        if en_texto:
            marca = en_texto[0]
            razon = f"La página menciona {marca.nombre} junto a un formulario de contraseña"
            frase = f"muestra la marca {marca.nombre} en un dominio que no es de {marca.nombre}"
        elif en_img := [(m, v) for m, v in marcas_en_imagenes(r.imagenes, marcas) if ajena(m)]:
            marca, evidencia = en_img[0]
            razon = f"La página muestra una imagen de {marca.nombre} («{evidencia[:60]}»)"
            frase = f"muestra el logo de {marca.nombre} en un dominio que no es de {marca.nombre}"
    if marca:
        h.append(Hallazgo("marca_en_pagina_ajena",
                          f"{razon}, pero «{dominio}» no es un dominio de {marca.nombre}.", frase))

    if r.formularios_password:
        if marca:
            h.append(Hallazgo("password_con_marca_ajena", f"Pide una contraseña haciéndose pasar "
                              f"por {marca.nombre}.", "pide tu contraseña"))
        else:
            h.append(Hallazgo("formulario_password", "La página tiene un formulario que pide "
                              "contraseña.", "pide una contraseña"))

    if r.permisos:
        nombres = {"geolocalizacion": "tu ubicación", "camara": "la cámara",
                   "microfono": "el micrófono", "notificaciones": "enviarte notificaciones"}
        pedidos = [nombres[x] for x in r.permisos]
        lista = ", ".join(pedidos[:-1]) + (" y " if len(pedidos) > 1 else "") + pedidos[-1]
        h.append(Hallazgo("permiso_sensible", f"La página pidió acceso a {lista} (el sandbox se "
                          "lo negó). Un sitio que acabas de abrir desde un QR rara vez lo necesita.",
                          f"pide acceso a {lista}"))

    descargas = [e for e in analisis.eventos if e.get("tipo") == "descarga_bloqueada"]
    if descargas:
        nombre = str(descargas[0].get("nombre", ""))[:60]
        h.append(Hallazgo("descarga", f"Intentó descargar un archivo automáticamente ({nombre}); "
                          "el sandbox lo bloqueó.", "intenta descargar un archivo"))

    if r.n_dominios_terceros > 20:
        h.append(Hallazgo("muchos_terceros", f"Contactó {r.n_dominios_terceros} dominios de "
                          "terceros.", f"contacta {r.n_dominios_terceros} dominios de terceros"))
    return h
