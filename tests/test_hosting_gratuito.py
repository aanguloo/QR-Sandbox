"""Señal de hosting gratuito con nombre generado (ejemplos solo del conjunto de DESARROLLO)."""

import pytest

from qrsandbox.senales import estaticas as E
from qrsandbox.senales.dominio import motivos_nombre_generado, partes_host, plataforma_gratuita
from qrsandbox.veredicto.motor import evaluar

from .test_senales import codigos


def test_detecta_la_plataforma_y_el_nombre():
    assert plataforma_gratuita(partes_host("https://sp30ct-zavur-biz-kemix-lonad.pages.dev/x")) == \
        ("pages.dev", "sp30ct-zavur-biz-kemix-lonad")
    assert plataforma_gratuita(partes_host("https://www.mi-cafe.vercel.app/")) == ("vercel.app", "mi-cafe")
    assert plataforma_gratuita(partes_host("https://pages.dev/")) is None  # la plataforma misma
    assert plataforma_gratuita(partes_host("https://www.bancoestado.cl/")) is None


@pytest.mark.parametrize("nombre", [
    "imjj-0k7yoh-r7qnfi-p3ou6q",              # mezcla letras y números al azar
    "melqavi-mpt-zunfelo-p2h8ka54",
    "nltay-6df-9snd-l6znz-08-09-2026-hh",     # fecha + fragmentos
    "jus-sup-21399932",                        # muchos dígitos
    "adebenewdocusmpdfmxbnmfeldocaventsenxz",  # tira larga sin separar
    "sp30ct-zavur-biz-kemix-lonad",           # muchos fragmentos con números
])
def test_nombres_generados_de_phishing(nombre):
    assert motivos_nombre_generado(nombre)


@pytest.mark.parametrize("nombre", [
    "cs231n",                              # número dentro de una palabra (curso de Stanford)
    "ml4a", "moba2d", "dl666123",
    "celadon-chaja-e416dc",                # nombre por defecto de Netlify
    "full-stack-web-and-mobile-template",  # descriptivo largo
    "astro-edge-functions-demo",
    "academicpages", "mi-cafe", "car-doctor-101",
])
def test_nombres_legitimos_no_parecen_generados(nombre):
    assert motivos_nombre_generado(nombre) == []


def test_puntajes_resultantes():
    # Hosting gratuito + nombre generado = 35: sospechoso.
    v = evaluar(E.analizar_url("https://imjj-0k7yoh-r7qnfi-p3ou6q.pages.dev/"))
    assert v["estado"] == "sospechoso" and v["puntaje"] == 35
    assert {"hosting_gratuito", "nombre_generado"} <= {r["codigo"] for r in v["razones"]}
    assert "nombre generado al azar" in v["resumen"]
    # Un proyecto legítimo con nombre normal: solo informa (10), sin alertas.
    v = evaluar(E.analizar_url("https://academicpages.github.io/"))
    assert v["estado"] == "sin_alertas" and v["puntaje"] == 10
    # Con imitación de marca, la plataforma suma a lo que ya alertaba.
    assert codigos(E.analizar_url("https://paypal-verify.vercel.app/").hallazgos) >= {
        "hosting_gratuito", "marca_en_dominio_ajeno"}
