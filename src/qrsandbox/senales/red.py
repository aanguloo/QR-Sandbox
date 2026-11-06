"""Señales que requieren red: edad del dominio (RDAP) y certificado TLS.

Son opcionales (`SENALES_RED=1`) y tienen timeout: si fallan, la señal simplemente no
aparece ("cuando sea posible").

Seguridad: obtener el certificado obliga a conectarse al host del ATACANTE desde la API.
Para que eso no sea un SSRF, se usa la MISMA política del proxy de salida: se resuelve el
nombre, se rechaza si alguna IP no es global y se conecta a la IP validada (con SNI = host).
Solo se hace el handshake TLS: no se envía ninguna petición HTTP.
RDAP se consulta en rdap.org (servicio fijo que redirige al registro de cada TLD), no en
el dominio analizado. Para `.cl` (NIC Chile no publica RDAP) se usa el whois de NIC Chile
(whois.nic.cl:43); el dominio se valida con una expresión estricta antes de enviarlo, así
no se puede inyectar nada en la consulta.
"""

import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from qrsandbox.proxy.politica import motivo_bloqueo

TIMEOUT_S = 4.0
WHOIS_CL = ("whois.nic.cl", 43)
_DOMINIO_SEGURO = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CREACION = re.compile(r"Creation date:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def fecha_creacion_whois(texto: str) -> datetime | None:
    m = _CREACION.search(texto)
    return datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=UTC) if m else None
TTL_CACHE_S = 3600
MAX_CACHE = 2000


@dataclass(frozen=True)
class InfoCertificado:
    valido: bool
    emisor: str
    emitido: datetime
    expira: datetime
    error: str | None = None


class ProveedorRed(Protocol):
    def edad_dominio_dias(self, registrable: str) -> int | None: ...
    def certificado(self, host: str) -> InfoCertificado | None: ...


class _Cache:
    def __init__(self):
        self._datos: dict[str, tuple[float, object]] = {}

    def obtener(self, clave: str, calcular):
        ahora = time.monotonic()
        if clave in self._datos and ahora - self._datos[clave][0] < TTL_CACHE_S:
            return self._datos[clave][1]
        valor = calcular()
        if len(self._datos) >= MAX_CACHE:
            self._datos.clear()
        self._datos[clave] = (ahora, valor)
        return valor


class ProveedorRedReal:
    def __init__(self, timeout: float = TIMEOUT_S, resolver=socket.getaddrinfo):
        self.timeout = timeout
        self.resolver = resolver
        self._cache = _Cache()

    # -------------------------------------------------------------- RDAP

    def edad_dominio_dias(self, registrable: str) -> int | None:
        # fullmatch (no match + "$"): "$" en Python acepta un "\n" final.
        if not registrable or not _DOMINIO_SEGURO.fullmatch(registrable):
            return None
        if registrable.endswith(".cl"):
            return self._cache.obtener(f"whois:{registrable}", lambda: self._whois_cl(registrable))
        return self._cache.obtener(f"rdap:{registrable}", lambda: self._rdap(registrable))

    def _whois_cl(self, registrable: str) -> int | None:
        try:
            with socket.create_connection(WHOIS_CL, timeout=self.timeout) as s:
                s.sendall(registrable.encode("ascii") + b"\r\n")
                datos = b""
                while len(datos) < 65536 and (trozo := s.recv(4096)):
                    datos += trozo
        except OSError:
            return None
        fecha = fecha_creacion_whois(datos.decode("utf-8", "replace"))
        return max(0, (datetime.now(UTC) - fecha).days) if fecha else None

    def _rdap(self, registrable: str) -> int | None:
        try:
            r = httpx.get(
                f"https://rdap.org/domain/{registrable}",
                timeout=self.timeout,
                follow_redirects=True,
                headers={"Accept": "application/rdap+json", "User-Agent": "QR-Sandbox (academico)"},
            )
            if r.status_code != 200:
                return None
            for evento in r.json().get("events", []):
                if evento.get("eventAction") == "registration":
                    fecha = datetime.fromisoformat(evento["eventDate"])
                    return max(0, (datetime.now(UTC) - fecha).days)
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, KeyError, TypeError):
            return None
        return None

    # -------------------------------------------------------------- TLS

    def certificado(self, host: str) -> InfoCertificado | None:
        return self._cache.obtener(f"tls:{host}", lambda: self._tls(host))

    def ip_validada(self, host: str) -> str | None:
        """Resuelve y aplica la política anti-SSRF. None si se bloquea o no resuelve."""
        try:
            infos = self.resolver(host, 443, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            return None
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        if not ips or any(motivo_bloqueo(ip, 443) for ip in ips):
            return None
        return ips[0]

    def _tls(self, host: str) -> InfoCertificado | None:
        ip = self.ip_validada(host)
        if ip is None:
            return None
        try:
            der, valido, error = self._handshake(ip, host, verificar=True), True, None
        except ssl.SSLCertVerificationError as e:
            try:
                der = self._handshake(ip, host, verificar=False)
            except (OSError, ssl.SSLError):
                return None
            valido, error = False, (e.verify_message or "no verificable")[:200]
        except (OSError, ssl.SSLError):
            return None
        cert = x509.load_der_x509_certificate(der)
        org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or \
            cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return InfoCertificado(
            valido=valido,
            emisor=str(org[0].value)[:100] if org else "desconocido",
            emitido=cert.not_valid_before_utc,
            expira=cert.not_valid_after_utc,
            error=error,
        )

    def _handshake(self, ip: str, host: str, verificar: bool) -> bytes:
        ctx = ssl.create_default_context()
        if not verificar:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=self.timeout) as s, \
                ctx.wrap_socket(s, server_hostname=host) as t:
            return t.getpeercert(binary_form=True)
