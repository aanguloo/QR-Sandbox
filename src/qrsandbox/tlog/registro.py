"""Registro firmado de un QR físico y formato canónico para firmar.

Un comercio firma con su clave Ed25519 los BYTES CANÓNICOS del registro:
    JSON con claves ordenadas alfabéticamente, sin espacios (separadores "," y ":"),
    UTF-8 sin escapar caracteres no ASCII.
El navegador (Fase 5) reproduce exactamente esos bytes construyendo el objeto con las
claves en orden alfabético y usando JSON.stringify. Por eso:
- las coordenadas van como ENTEROS en microgrados (lat_e6 = lat * 10^6): los floats
  se serializan distinto en Python y en JavaScript;
- el timestamp es un entero (segundos Unix);
- la URL debe venir ya normalizada (si no, la firma cubriría otra cadena);
- el campo `v` separa dominios: una firma de registro no sirve como firma de otra cosa.
"""

import base64
import binascii
import json
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from qrsandbox.comun.esquemas import MAX_URL, normalizar_url

VERSION_REGISTRO = "qrtlog-registro-v1"
VERSION_REVOCACION = "qrtlog-revocacion-v1"
VERSION_STH = "qrtlog-sth-v1"


def bytes_canonicos(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def de_b64(texto: str, largo: int | None = None) -> bytes:
    try:
        datos = base64.b64decode(texto, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("base64 inválido") from None
    if largo is not None and len(datos) != largo:
        raise ValueError(f"se esperaban {largo} bytes")
    return datos


def _url_ya_normalizada(url: str) -> str:
    if normalizar_url(url) != url:
        raise ValueError(f"la URL debe venir normalizada: {normalizar_url(url)}")
    return url


def _clave_publica_valida(texto: str) -> str:
    de_b64(texto, 32)
    return texto


def _sin_control(texto: str) -> str:
    if any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in texto):
        raise ValueError("caracteres de control no permitidos")
    return texto


ClavePublica = Annotated[str, StringConstraints(max_length=64), AfterValidator(_clave_publica_valida)]
Firma = Annotated[str, StringConstraints(max_length=128)]


class Registro(BaseModel):
    """Lo que el comercio firma. Todos los campos quedan públicos en el log."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    v: Literal["qrtlog-registro-v1"]
    # str crudo (no el tipo Url, que normaliza en silencio): la firma cubre exactamente
    # esta cadena, así que exigimos que ya venga normalizada.
    url_destino: Annotated[
        str, StringConstraints(max_length=MAX_URL), AfterValidator(_url_ya_normalizada)
    ]
    lat_e6: Annotated[int, Field(ge=-90_000_000, le=90_000_000)]
    lon_e6: Annotated[int, Field(ge=-180_000_000, le=180_000_000)]
    radio_m: Annotated[int, Field(ge=5, le=500)]
    descripcion: Annotated[str, StringConstraints(max_length=200), AfterValidator(_sin_control)]
    timestamp: Annotated[int, Field(ge=0)]
    clave_publica: ClavePublica

    def canonico(self) -> bytes:
        return bytes_canonicos(self.model_dump())


class SolicitudRegistro(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    registro: Registro
    firma: Firma


class Revocacion(BaseModel):
    """El comercio retira un QR que ya no usa (o que registró por error).

    Solo la MISMA clave que firmó el registro puede revocarlo (lo verifica el log y
    cualquier auditor). Es una hoja más del log: la revocación también queda auditada y
    el registro original no se borra (append-only).
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    v: Literal["qrtlog-revocacion-v1"]
    indice: Annotated[int, Field(ge=0)]  # hoja del registro que se revoca
    motivo: Annotated[str, StringConstraints(max_length=200), AfterValidator(_sin_control)]
    timestamp: Annotated[int, Field(ge=0)]
    clave_publica: ClavePublica

    def canonico(self) -> bytes:
        return bytes_canonicos(self.model_dump())


class SolicitudRevocacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    revocacion: Revocacion
    firma: Firma


# ---------------------------------------------------------------- firmas Ed25519


def clave_publica_b64(clave: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    publica = clave.public_key() if isinstance(clave, Ed25519PrivateKey) else clave
    return b64(publica.public_bytes(Encoding.Raw, PublicFormat.Raw))


def firmar(clave: Ed25519PrivateKey, mensaje: bytes) -> str:
    return b64(clave.sign(mensaje))


def verificar_firma(clave_publica: str, mensaje: bytes, firma: str) -> bool:
    try:
        publica = Ed25519PublicKey.from_public_bytes(de_b64(clave_publica, 32))
        publica.verify(de_b64(firma, 64), mensaje)
        return True
    except (ValueError, InvalidSignature):
        return False


def firmar_registro(clave: Ed25519PrivateKey, **campos) -> SolicitudRegistro:
    """Ayuda para tests, scripts y el Experimento 3 (en producción firma el navegador)."""
    registro = Registro(v=VERSION_REGISTRO, clave_publica=clave_publica_b64(clave), **campos)
    return SolicitudRegistro(registro=registro, firma=firmar(clave, registro.canonico()))


def firmar_revocacion(clave: Ed25519PrivateKey, **campos) -> SolicitudRevocacion:
    r = Revocacion(v=VERSION_REVOCACION, clave_publica=clave_publica_b64(clave), **campos)
    return SolicitudRevocacion(revocacion=r, firma=firmar(clave, r.canonico()))


def mensaje_sth(tamano: int, raiz: bytes, timestamp_ms: int) -> bytes:
    """Bytes que firma el log para su Signed Tree Head."""
    return bytes_canonicos(
        {"v": VERSION_STH, "tamano": tamano, "raiz": raiz.hex(), "timestamp_ms": timestamp_ms}
    )
