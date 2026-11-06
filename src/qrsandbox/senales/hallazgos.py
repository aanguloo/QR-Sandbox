"""Hallazgos y su peso en el puntaje (0–100). Tabla ÚNICA y explícita: nada de cajas negras.

Criterio de los pesos (defendible en la presentación):
- ≥ 60: por sí solo casi prueba engaño (lista negra, sticker detectado por el log,
  homoglifos que imitan una marca).
- 30–55: fuerte, pero con usos legítimos posibles (dominio de días, marca en dominio ajeno).
- 10–25: débil; solo suma junto a otros (TLD barato, acortador, muchas redirecciones).
- negativos: evidencia a favor (QR verificado en el log).
Umbrales del estado: ≥ 70 peligroso, 35–69 sospechoso, < 35 sin alertas.
"""

from dataclasses import dataclass

PESOS: dict[str, int] = {
    # QR Transparency Log
    "log_no_coincide": 60,
    "log_verificado": -40,
    # listas negras
    "lista_negra_url": 90,
    "lista_negra_dominio": 40,
    # suplantación de marca en el dominio
    "homoglifos_marca": 60,
    "sustitucion_marca": 55,
    "typosquatting_marca": 45,
    "marca_en_dominio_ajeno": 35,
    "punycode": 15,
    # rastreo y permisos
    "rastreador_ip": 40,  # el enlace pasa por un "IP logger"
    "permiso_sensible": 20,  # la página pidió ubicación, cámara, micrófono o notificaciones
    # forma de la URL
    "userinfo_arroba": 35,
    "ip_literal": 30,
    "sin_https": 15,
    "tld_riesgoso": 15,
    "acortador": 10,
    "puerto_no_estandar": 10,
    "muchos_subdominios": 10,
    "palabras_clave": 10,
    # red (cuando se pudo consultar)
    "dominio_muy_nuevo": 40,
    "dominio_nuevo": 25,
    "certificado_invalido": 25,
    "certificado_reciente": 10,
    # dinámicas (sandbox)
    "marca_en_pagina_ajena": 30,
    "password_con_marca_ajena": 35,
    "formulario_password": 15,
    "descarga": 20,
    "muchas_redirecciones": 15,
    "cambio_de_dominio": 10,
    "muchos_terceros": 5,
}


@dataclass(frozen=True)
class Hallazgo:
    codigo: str
    razon: str  # oración completa para la lista de razones
    frase: str  # fragmento corto para el resumen ("usa un 0 en lugar de una o")

    @property
    def peso(self) -> int:
        return PESOS[self.codigo]

    def a_dict(self) -> dict:
        return {"codigo": self.codigo, "peso": self.peso, "razon": self.razon}
