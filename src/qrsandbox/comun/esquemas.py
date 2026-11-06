"""Esquemas pydantic para los datos que cruzan fronteras de confianza.

Todo lo que sale del worker es *tainted* (idea de RLBox): el worker visita páginas
hostiles y puede estar comprometido, así que puede mentir o mandar basura. Por eso
cada evento se valida contra un esquema CERRADO:
- `tipo` de una lista fija (unión discriminada); cualquier otro tipo se rechaza.
- `extra="forbid"`: campos no previstos invalidan el evento.
- Largos máximos en todos los strings y listas (anti-DoS / anti-memoria).
- URLs solo http/https (nada de `javascript:`, `data:`, `file:`...).
"""

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter

MAX_URL = 2048
MAX_DOMINIO = 253  # largo máximo de un nombre DNS
MAX_CAPTURA_B64 = 280_000  # ~200 KB de JPEG en base64


def _validar_url(valor: str) -> str:
    partes = urlsplit(valor)
    if partes.scheme not in ("http", "https"):
        raise ValueError("solo se permiten URLs http/https")
    if not partes.hostname:
        raise ValueError("URL sin host")
    # Caracteres de control en una URL son señal de inyección (cabeceras, logs).
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in valor):
        raise ValueError("URL con caracteres de control")
    return valor


Url = Annotated[str, StringConstraints(max_length=MAX_URL), AfterValidator(_validar_url)]
Dominio = Annotated[str, StringConstraints(max_length=MAX_DOMINIO, pattern=r"^[A-Za-z0-9.\-:\[\]]+$")]
TextoCorto = Annotated[str, StringConstraints(max_length=500)]
Ms = Annotated[int, Field(ge=0, le=120_000)]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ResultadoWorker(_Base):
    """Resumen final que el worker dice haber observado (sigue siendo tainted)."""

    url_inicial: Url
    url_final: Url | None
    cadena_redirecciones: Annotated[list[Url], Field(max_length=30)]
    titulo: Annotated[str, StringConstraints(max_length=300)]
    estado_http: Annotated[int, Field(ge=100, le=599)] | None
    formularios_password: Annotated[int, Field(ge=0, le=1000)]
    dominios_terceros: Annotated[list[Dominio], Field(max_length=50)]
    n_dominios_terceros: Annotated[int, Field(ge=0, le=100_000)]
    tiempo_carga_ms: Ms | None


class EvRedireccion(_Base):
    tipo: Literal["redireccion"]
    t_ms: Ms
    desde: Url
    hacia: Url


class EvNavegacion(_Base):
    tipo: Literal["navegacion"]
    t_ms: Ms
    url: Url


class EvRequestTercero(_Base):
    tipo: Literal["request_tercero"]
    t_ms: Ms
    dominio: Dominio


class EvFormularioPassword(_Base):
    tipo: Literal["formulario_password"]
    t_ms: Ms
    cantidad: Annotated[int, Field(ge=1, le=1000)]


class EvDescargaBloqueada(_Base):
    tipo: Literal["descarga_bloqueada"]
    t_ms: Ms
    url: Url
    nombre: Annotated[str, StringConstraints(max_length=255)]


class EvMarcaDetectada(_Base):
    tipo: Literal["marca_detectada"]
    t_ms: Ms
    marca: Annotated[str, StringConstraints(max_length=64)]
    dominio: Dominio


class EvCaptura(_Base):
    tipo: Literal["captura"]
    t_ms: Ms
    jpeg_b64: Annotated[str, StringConstraints(max_length=MAX_CAPTURA_B64)]


class EvFin(_Base):
    tipo: Literal["fin"]
    t_ms: Ms
    resultado: ResultadoWorker | None


class EvError(_Base):
    tipo: Literal["error"]
    t_ms: Ms
    mensaje: TextoCorto


Evento = Annotated[
    EvRedireccion
    | EvNavegacion
    | EvRequestTercero
    | EvFormularioPassword
    | EvDescargaBloqueada
    | EvMarcaDetectada
    | EvCaptura
    | EvFin
    | EvError,
    Field(discriminator="tipo"),
]

# Valida directamente desde los bytes JSON (modo estricto: un "3" no pasa por 3).
ADAPTADOR_EVENTO: TypeAdapter[Evento] = TypeAdapter(Evento)


class SolicitudAnalisis(BaseModel):
    """Entrada de la API y del orquestador: solo una URL (interfaz estrecha)."""

    model_config = ConfigDict(extra="forbid")
    url: Url


class ResultadoAnalisis(BaseModel):
    """Respuesta del orquestador a la API (producida por código propio, ya validado)."""

    id: str
    url: str
    runtime: str
    duracion_ms: int
    codigo_salida: int | None
    timeout: bool
    salida_excedida: bool
    eventos: list[dict]  # eventos ya validados (sin la captura, que va aparte)
    eventos_descartados: int
    resultado: ResultadoWorker | None
    captura_jpeg_b64: str | None
    contenedor_eliminado: bool
    error: str | None = None
