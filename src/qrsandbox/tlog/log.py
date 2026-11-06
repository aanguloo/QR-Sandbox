"""QR Transparency Log: log append-only de registros de QRs físicos.

Garantías (como en Certificate Transparency):
- Cada registro lleva la firma Ed25519 del comercio: nadie puede registrar a nombre de
  una clave que no posee (Adversario C). La identidad legal NO se prueba (como un
  certificado DV): solo la posesión de la clave.
- Tras cada inserción el log firma un Signed Tree Head (STH) con su propia clave.
  Con pruebas de inclusión cualquiera verifica que un registro está en el árbol firmado,
  y con pruebas de consistencia que el log solo crece (no reescribe el historial).
- SQLite con triggers que impiden UPDATE/DELETE. No es la garantía real (quien controla
  la BD puede quitarlos): la garantía real es criptográfica. Si alguien altera una hoja,
  la raíz recalculada ya no coincide con el STH firmado, y los auditores lo detectan.
  Por eso las pruebas se calculan SIEMPRE desde los datos crudos, nunca desde un hash
  guardado que un atacante podría dejar intacto.
"""

import json
import math
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qrsandbox.comun.esquemas import normalizar_url
from qrsandbox.tlog import merkle
from qrsandbox.tlog.registro import (
    Registro,
    Revocacion,
    SolicitudRegistro,
    SolicitudRevocacion,
    bytes_canonicos,
    clave_publica_b64,
    firmar,
    mensaje_sth,
    verificar_firma,
)

TOLERANCIA_TIMESTAMP_S = 600  # el registro debe estar firmado hace menos de 10 min
MARGEN_UBICACION_M = 100  # imprecisión del GPS + redondeo de privacidad
DECIMALES_PRIVACIDAD = 3  # ~110 m: la ubicación del escaneo se redondea en el servidor
RADIO_TIERRA_M = 6_371_000

ESQUEMA = """
CREATE TABLE IF NOT EXISTS hojas (
    indice        INTEGER PRIMARY KEY,
    datos         BLOB NOT NULL,          -- bytes canónicos de la hoja (lo que se hashea)
    hash          BLOB NOT NULL UNIQUE,   -- solo para evitar duplicados; no se usa en pruebas
    clave_publica TEXT NOT NULL,
    url           TEXT NOT NULL,
    lat_e6        INTEGER NOT NULL,
    lon_e6        INTEGER NOT NULL,
    radio_m       INTEGER NOT NULL,
    t_log_ms      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hojas_ubicacion ON hojas (lat_e6, lon_e6);
CREATE INDEX IF NOT EXISTS hojas_clave ON hojas (clave_publica);
CREATE TABLE IF NOT EXISTS sths (
    tamano       INTEGER PRIMARY KEY,
    raiz         BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    firma        TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS hojas_sin_update BEFORE UPDATE ON hojas
    BEGIN SELECT RAISE(ABORT, 'log append-only: no se pueden modificar hojas'); END;
CREATE TRIGGER IF NOT EXISTS hojas_sin_delete BEFORE DELETE ON hojas
    BEGIN SELECT RAISE(ABORT, 'log append-only: no se pueden borrar hojas'); END;
CREATE TRIGGER IF NOT EXISTS sths_sin_update BEFORE UPDATE ON sths
    BEGIN SELECT RAISE(ABORT, 'log append-only: no se pueden modificar STHs'); END;
CREATE TRIGGER IF NOT EXISTS sths_sin_delete BEFORE DELETE ON sths
    BEGIN SELECT RAISE(ABORT, 'log append-only: no se pueden borrar STHs'); END;
"""


class RegistroRechazado(ValueError):
    """El registro no cumple las reglas del log (firma, frescura, duplicado...)."""


def cargar_o_crear_clave(ruta: Path) -> Ed25519PrivateKey:
    """Clave del log. Se crea con permisos 0600 si no existe."""
    if ruta.exists():
        return serialization.load_pem_private_key(ruta.read_bytes(), password=None)
    clave = Ed25519PrivateKey.generate()
    ruta.parent.mkdir(parents=True, exist_ok=True)
    pem = clave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as f:
        f.write(pem)
    return clave


def distancia_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distancia haversine en metros."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * RADIO_TIERRA_M * math.asin(math.sqrt(a))


def misma_url(a: str, b: str) -> bool:
    """Compara URLs normalizadas; una ruta vacía equivale a "/"."""

    def clave(u: str) -> str:
        n = normalizar_url(u)
        esquema, resto = n.split("://", 1)
        if "/" not in resto.split("?", 1)[0]:
            resto = resto.replace("?", "/?", 1) if "?" in resto else resto + "/"
        return f"{esquema}://{resto}"

    try:
        return clave(a) == clave(b)
    except ValueError:
        return False


@dataclass(frozen=True)
class STH:
    tamano: int
    raiz: bytes
    timestamp_ms: int
    firma: str

    def a_dict(self) -> dict:
        return {
            "tamano": self.tamano,
            "raiz": self.raiz.hex(),
            "timestamp_ms": self.timestamp_ms,
            "firma": self.firma,
        }


class LogTransparencia:
    def __init__(self, ruta_db: Path | str, clave: Ed25519PrivateKey, reloj=time.time):
        self.ruta_db = str(ruta_db)
        self.clave = clave
        self.clave_publica = clave_publica_b64(clave)
        self.reloj = reloj
        self._lock = threading.Lock()
        con = sqlite3.connect(self.ruta_db)
        try:
            con.executescript(ESQUEMA)  # hace su propio COMMIT: va fuera de _conexion()
            # Migración (Fase 5): tipo de hoja y revocaciones. ADD COLUMN no reescribe filas.
            columnas = {c[1] for c in con.execute("PRAGMA table_info(hojas)")}
            if "tipo" not in columnas:
                con.execute("ALTER TABLE hojas ADD COLUMN tipo TEXT NOT NULL DEFAULT 'registro'")
            if "revoca" not in columnas:
                con.execute("ALTER TABLE hojas ADD COLUMN revoca INTEGER")
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS hojas_revoca ON hojas (revoca)")
            con.commit()
        finally:
            con.close()
        with self._conexion() as con:
            if con.execute("SELECT COUNT(*) FROM sths").fetchone()[0] == 0:
                self._firmar_sth(con, [])

    @contextmanager
    def _conexion(self) -> Iterator[sqlite3.Connection]:
        """Conexión corta: commit si todo sale bien, rollback si hay excepción, y cierre."""
        con = sqlite3.connect(self.ruta_db, timeout=10, isolation_level=None)
        try:
            con.execute("BEGIN")
            yield con
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    # ------------------------------------------------------------ escritura

    def agregar(self, solicitud: SolicitudRegistro) -> dict:
        """Valida y agrega un registro. Devuelve el recibo de inclusión."""
        r = solicitud.registro
        if not verificar_firma(r.clave_publica, r.canonico(), solicitud.firma):
            raise RegistroRechazado("firma inválida")
        ahora = self.reloj()
        if abs(ahora - r.timestamp) > TOLERANCIA_TIMESTAMP_S:
            raise RegistroRechazado("timestamp fuera de la ventana permitida (±10 min)")

        t_log_ms = int(ahora * 1000)
        datos = bytes_canonicos(
            {"registro": r.model_dump(), "firma": solicitud.firma, "t_log_ms": t_log_ms}
        )
        with self._lock, self._conexion() as con:
            # Anti-replay: una solicitud firmada solo se acepta UNA vez. Sin esto, quien
            # guardó la solicitud original podría reactivar un QR que el comercio revocó.
            for (anterior,) in con.execute(
                "SELECT datos FROM hojas WHERE tipo = 'registro' AND clave_publica = ? AND url = ?",
                (r.clave_publica, r.url_destino),
            ):
                if json.loads(anterior)["firma"] == solicitud.firma:
                    raise RegistroRechazado("registro repetido: esa solicitud firmada ya se usó")
            if con.execute(
                "SELECT 1 FROM hojas WHERE tipo = 'registro' AND clave_publica = ? AND url = ? "
                "AND lat_e6 = ? AND lon_e6 = ? AND radio_m = ? AND indice NOT IN "
                "(SELECT revoca FROM hojas WHERE revoca IS NOT NULL)",
                (r.clave_publica, r.url_destino, r.lat_e6, r.lon_e6, r.radio_m),
            ).fetchone():
                raise RegistroRechazado("registro duplicado")
            return self._insertar(
                con, datos, r.clave_publica, r.url_destino, r.lat_e6, r.lon_e6, r.radio_m,
                t_log_ms, "registro", None,
            )

    def revocar(self, solicitud: SolicitudRevocacion) -> dict:
        """Agrega una revocación firmada por la MISMA clave que registró el QR."""
        rv = solicitud.revocacion
        if not verificar_firma(rv.clave_publica, rv.canonico(), solicitud.firma):
            raise RegistroRechazado("firma inválida")
        ahora = self.reloj()
        if abs(ahora - rv.timestamp) > TOLERANCIA_TIMESTAMP_S:
            raise RegistroRechazado("timestamp fuera de la ventana permitida (±10 min)")
        t_log_ms = int(ahora * 1000)
        datos = bytes_canonicos(
            {"revocacion": rv.model_dump(), "firma": solicitud.firma, "t_log_ms": t_log_ms}
        )
        with self._lock, self._conexion() as con:
            fila = con.execute(
                "SELECT tipo, clave_publica, url, lat_e6, lon_e6, radio_m FROM hojas "
                "WHERE indice = ?", (rv.indice,),
            ).fetchone()
            if fila is None:
                raise RegistroRechazado("no existe un registro con ese índice")
            tipo, clave, url, lat_e6, lon_e6, radio_m = fila
            if tipo != "registro":
                raise RegistroRechazado("solo se pueden revocar registros")
            if clave != rv.clave_publica:
                # Adversario C: nadie puede retirar el QR de otro comercio.
                raise RegistroRechazado("solo la clave que registró el QR puede revocarlo")
            if con.execute("SELECT 1 FROM hojas WHERE revoca = ?", (rv.indice,)).fetchone():
                raise RegistroRechazado("ese registro ya está revocado")
            return self._insertar(
                con, datos, clave, url, lat_e6, lon_e6, radio_m, t_log_ms, "revocacion", rv.indice
            )

    def _insertar(self, con, datos, clave, url, lat_e6, lon_e6, radio_m, t_log_ms, tipo, revoca):
        # El lock serializa escrituras en este proceso; BEGIN es suficiente con un solo
        # escritor (la API). El índice es el número de hojas: secuencial y sin huecos.
        indice = con.execute("SELECT COUNT(*) FROM hojas").fetchone()[0]
        con.execute(
            "INSERT INTO hojas (indice, datos, hash, clave_publica, url, lat_e6, lon_e6, "
            "radio_m, t_log_ms, tipo, revoca) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (indice, datos, merkle.hash_hoja(datos), clave, url, lat_e6, lon_e6, radio_m,
             t_log_ms, tipo, revoca),
        )
        hojas = self._hashes(con)
        sth = self._firmar_sth(con, hojas)
        return {
            "indice": indice,
            "hoja": datos.decode(),
            "hash_hoja": merkle.hash_hoja(datos).hex(),
            "sth": sth.a_dict(),
            "prueba_inclusion": [h.hex() for h in merkle.ruta_inclusion(indice, hojas)],
            "clave_log": self.clave_publica,
        }

    def _firmar_sth(self, con: sqlite3.Connection, hojas: list[bytes]) -> STH:
        raiz = merkle.raiz(hojas)
        ts = int(self.reloj() * 1000)
        sth = STH(len(hojas), raiz, ts, firmar(self.clave, mensaje_sth(len(hojas), raiz, ts)))
        con.execute(
            "INSERT OR IGNORE INTO sths VALUES (?, ?, ?, ?)",
            (sth.tamano, sth.raiz, sth.timestamp_ms, sth.firma),
        )
        return sth

    # ------------------------------------------------------------ lectura

    @staticmethod
    def _hashes(con: sqlite3.Connection, tamano: int | None = None) -> list[bytes]:
        """Hashes de hoja recalculados desde los datos crudos."""
        sql = "SELECT datos FROM hojas ORDER BY indice"
        filas = con.execute(sql + (" LIMIT ?" if tamano is not None else ""),
                            (tamano,) if tamano is not None else ()).fetchall()
        return [merkle.hash_hoja(f[0]) for f in filas]

    def tamano(self) -> int:
        with self._conexion() as con:
            return con.execute("SELECT COUNT(*) FROM hojas").fetchone()[0]

    def sth(self, tamano: int | None = None) -> STH | None:
        with self._conexion() as con:
            if tamano is None:
                fila = con.execute("SELECT * FROM sths ORDER BY tamano DESC LIMIT 1").fetchone()
            else:
                fila = con.execute("SELECT * FROM sths WHERE tamano = ?", (tamano,)).fetchone()
        return STH(fila[0], bytes(fila[1]), fila[2], fila[3]) if fila else None

    def sths(self) -> list[STH]:
        with self._conexion() as con:
            filas = con.execute("SELECT * FROM sths ORDER BY tamano").fetchall()
        return [STH(f[0], bytes(f[1]), f[2], f[3]) for f in filas]

    def entrada(self, indice: int) -> dict | None:
        with self._conexion() as con:
            fila = con.execute("SELECT datos FROM hojas WHERE indice = ?", (indice,)).fetchone()
        return {"indice": indice, "hoja": fila[0].decode()} if fila else None

    def entradas(self, desde: int = 0, limite: int = 100) -> list[dict]:
        with self._conexion() as con:
            filas = con.execute(
                "SELECT indice, datos FROM hojas WHERE indice >= ? ORDER BY indice LIMIT ?",
                (desde, limite),
            ).fetchall()
        return [{"indice": i, "hoja": d.decode()} for i, d in filas]

    def por_clave(self, clave_publica: str) -> list[dict]:
        """Auditoría: todo lo registrado con una clave (¿alguien registró a mi nombre?)."""
        with self._conexion() as con:
            filas = con.execute(
                "SELECT indice, datos FROM hojas WHERE clave_publica = ? ORDER BY indice",
                (clave_publica,),
            ).fetchall()
        return [{"indice": i, "hoja": d.decode()} for i, d in filas]

    def prueba_inclusion(self, indice: int, tamano: int) -> list[bytes]:
        with self._conexion() as con:
            hojas = self._hashes(con, tamano)
        if tamano > len(hojas):
            raise ValueError("tamaño mayor que el log")
        return merkle.ruta_inclusion(indice, hojas)

    def prueba_consistencia(self, primero: int, segundo: int) -> list[bytes]:
        with self._conexion() as con:
            hojas = self._hashes(con, segundo)
        if segundo > len(hojas) or not 0 < primero <= segundo:
            raise ValueError("tamaños inválidos")
        return merkle.prueba_consistencia(primero, hojas)

    def verificar_integridad(self) -> tuple[bool, str]:
        """Recalcula todo desde los datos crudos y lo compara con los STHs firmados."""
        with self._conexion() as con:
            hojas = self._hashes(con)
        for sth in self.sths():
            mensaje = mensaje_sth(sth.tamano, sth.raiz, sth.timestamp_ms)
            if not verificar_firma(self.clave_publica, mensaje, sth.firma):
                return False, f"firma inválida en el STH de tamaño {sth.tamano}"
            if sth.tamano > len(hojas):
                return False, f"el STH de tamaño {sth.tamano} supera las hojas guardadas"
            if merkle.raiz(hojas[: sth.tamano]) != sth.raiz:
                return False, f"la raíz recalculada no coincide con el STH de tamaño {sth.tamano}"
        return True, f"{len(hojas)} hojas consistentes con {len(self.sths())} STHs firmados"

    # ------------------------------------------------------------ consulta al escanear

    def consultar(
        self, url: str, lat: float, lon: float, margen_m: float = MARGEN_UBICACION_M
    ) -> dict:
        """Estado del QR escaneado en (lat, lon).

        Privacidad: la ubicación se redondea a ~110 m ANTES de usarla y no se guarda.
        """
        lat = round(lat, DECIMALES_PRIVACIDAD)
        lon = round(lon, DECIMALES_PRIVACIDAD)
        alcance = 500 + margen_m  # radio máximo de un registro + margen
        dlat = alcance / 111_320
        dlon = alcance / (111_320 * max(0.01, math.cos(math.radians(lat))))
        with self._conexion() as con:
            revocados = {f[0] for f in con.execute(
                "SELECT revoca FROM hojas WHERE revoca IS NOT NULL").fetchall()}
            filas = con.execute(
                "SELECT indice, datos, url, lat_e6, lon_e6, radio_m FROM hojas "
                "WHERE tipo = 'registro' AND lat_e6 BETWEEN ? AND ? AND lon_e6 BETWEEN ? AND ?",
                (int((lat - dlat) * 1e6), int((lat + dlat) * 1e6),
                 int((lon - dlon) * 1e6), int((lon + dlon) * 1e6)),
            ).fetchall()
            hojas = self._hashes(con)
        sth = self.sth()
        coincidencias, otros, revocados_cercanos = [], [], []
        for indice, datos, url_reg, lat_e6, lon_e6, radio_m in filas:
            d = distancia_m(lat, lon, lat_e6 / 1e6, lon_e6 / 1e6)
            if d > radio_m + margen_m or indice >= sth.tamano:
                continue
            entrada = {"indice": indice, "hoja": datos.decode(), "distancia_m": round(d)}
            if indice in revocados:
                # Un QR retirado por su comercio no verifica ni alerta; se informa aparte.
                revocados_cercanos.append(entrada)
            elif misma_url(url, url_reg):
                ruta = merkle.ruta_inclusion(indice, hojas[: sth.tamano])
                entrada["prueba_inclusion"] = [h.hex() for h in ruta]
                coincidencias.append(entrada)
            else:
                otros.append(entrada)
        estado = "verificado" if coincidencias else "no_coincide" if otros else "sin_registro"
        return {
            "estado": estado,
            "coincidencias": coincidencias,
            "otros_destinos_cercanos": otros,
            "revocados_cercanos": revocados_cercanos,
            "sth": sth.a_dict(),
            "clave_log": self.clave_publica,
            "ubicacion_usada": {"lat": lat, "lon": lon},
        }


def leer_hoja(texto: str) -> tuple[Registro, str, int]:
    """Decodifica una hoja de REGISTRO (ValueError si es otra cosa)."""
    d = json.loads(texto)
    if "registro" not in d:
        raise ValueError("la hoja no es un registro")
    return Registro.model_validate(d["registro"]), d["firma"], d["t_log_ms"]


def leer_entrada(texto: str) -> tuple[str, Registro | Revocacion, str, int]:
    """Decodifica cualquier hoja: ("registro" | "revocacion", modelo, firma, t_log_ms)."""
    d = json.loads(texto)
    if "registro" in d:
        return "registro", Registro.model_validate(d["registro"]), d["firma"], d["t_log_ms"]
    if "revocacion" in d:
        return "revocacion", Revocacion.model_validate(d["revocacion"]), d["firma"], d["t_log_ms"]
    raise ValueError("hoja de tipo desconocido")

