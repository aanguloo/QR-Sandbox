"""Listas negras públicas y lista de sitios populares, consultadas OFFLINE.

`scripts/descargar_listas.py` guarda snapshots CON FECHA en `data/listas/snapshots/` y
construye un índice SQLite (`data/listas/listas.sqlite`) que la API abre en solo lectura.
- Consultar offline evita filtrar a terceros qué URLs escanean los usuarios.
- Los snapshots con fecha hacen reproducibles los experimentos y permiten separar por
  tiempo (lista negra de ayer vs. URLs de hoy): así se mide honestamente que "las listas
  negras llegan tarde", sin que la lista contenga ya el conjunto de prueba.
- SQLite en vez de un `set` en memoria: la lista de dominios tiene cientos de miles.

Tipos de archivo (en el directorio o en `snapshots/`):
    urls-<fuente>-<fecha>.txt      una URL por línea (se acumulan todos los snapshots)
    dominios-<fuente>-<fecha>.txt  un dominio por línea (solo el snapshot más reciente)
    tranco-<fecha>.csv             "rango,dominio" (solo el más reciente)
    <otro>.txt                     se trata como lista de URLs
"""

import os
import re
import sqlite3
import threading
from pathlib import Path

from qrsandbox.comun.esquemas import normalizar_url
from qrsandbox.senales.dominio import partes_host

PLATAFORMAS_COMPARTIDAS = {
    "google.com", "googleusercontent.com", "github.io", "githubusercontent.com", "web.app",
    "firebaseapp.com", "weebly.com", "wixsite.com", "blogspot.com", "sharepoint.com",
    "dropbox.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "glitch.me",
    "000webhostapp.com", "azurewebsites.net", "amazonaws.com", "cloudfront.net",
    "ipfs.io", "forms.gle", "notion.site", "linktr.ee", "canva.site", "r2.dev",
}
# Un dominio en el top N de Tranco no se marca por coincidencia de DOMINIO ni como
# imitación de marca (sí por coincidencia de URL exacta: un sitio popular puede estar
# comprometido).
TOP_POPULARES = int(os.environ.get("TOP_POPULARES", "100000"))

ESQUEMA = """
CREATE TABLE IF NOT EXISTS urls (clave TEXT PRIMARY KEY, fuente TEXT, fecha TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hosts (host TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dominios (dominio TEXT PRIMARY KEY, fuente TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS populares (dominio TEXT PRIMARY KEY, rango INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fuentes (nombre TEXT PRIMARY KEY, entradas INTEGER, fechas TEXT);
"""
_NOMBRE = re.compile(r"^(urls|dominios|tranco)-?(.*?)-?(\d{4}-\d{2}-\d{2})?$")


def clave_url(url: str) -> str | None:
    try:
        n = normalizar_url(url.strip())
    except ValueError:
        return None
    return n if n.count("/") > 2 else n + "/"


def _lineas(archivo: Path):
    with archivo.open(encoding="utf-8", errors="replace") as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                yield linea


def _clasificar(archivo: Path) -> tuple[str, str, str]:
    """(tipo, fuente, fecha) a partir del nombre del archivo."""
    m = _NOMBRE.match(archivo.stem)
    if archivo.suffix == ".csv" and archivo.stem.startswith("tranco"):
        return "tranco", "tranco", (m.group(3) if m else "") or ""
    if m and m.group(1) in ("urls", "dominios"):
        return m.group(1), m.group(2) or m.group(1), m.group(3) or ""
    return "urls", archivo.stem, ""


def construir(con: sqlite3.Connection, directorio: Path) -> dict[str, int]:
    """Carga los archivos de `directorio` (y `snapshots/`) en las tablas."""
    con.executescript(ESQUEMA)
    archivos = sorted(
        [*directorio.glob("*.txt"), *directorio.glob("*.csv"),
         *directorio.glob("snapshots/*.txt"), *directorio.glob("snapshots/*.csv")]
    )
    por_tipo: dict[tuple[str, str], list[tuple[str, Path]]] = {}
    for a in archivos:
        tipo, fuente, fecha = _clasificar(a)
        por_tipo.setdefault((tipo, fuente), []).append((fecha, a))
    resumen = {}
    for (tipo, fuente), lista in por_tipo.items():
        lista.sort()
        if tipo != "urls":
            lista = lista[-1:]  # dominios y Tranco: solo el snapshot más reciente
        n = 0
        for fecha, archivo in lista:
            if tipo == "urls":
                filas = [(c, fuente, fecha) for ln in _lineas(archivo) if (c := clave_url(ln))]
                con.executemany("INSERT OR IGNORE INTO urls VALUES (?, ?, ?)", filas)
                con.executemany("INSERT OR IGNORE INTO hosts VALUES (?)",
                                [(partes_host(c).host,) for c, _, _ in filas])
            elif tipo == "dominios":
                filas = [(d.lower(), fuente) for d in _lineas(archivo) if " " not in d]
                con.executemany("INSERT OR IGNORE INTO dominios VALUES (?, ?)", filas)
            else:
                filas = []
                for ln in _lineas(archivo):
                    rango, _, dominio = ln.partition(",")
                    if rango.isdigit() and dominio:
                        filas.append((dominio.strip().lower(), int(rango)))
                con.executemany("INSERT OR IGNORE INTO populares VALUES (?, ?)", filas)
            n += len(filas)
        fechas = ",".join(f for f, _ in lista if f)
        con.execute("INSERT OR REPLACE INTO fuentes VALUES (?, ?, ?)", (fuente, n, fechas))
        resumen[fuente] = n
    con.commit()
    return resumen


def construir_indice(directorio: Path, salida: Path) -> dict[str, int]:
    """Construye el índice SQLite en un archivo temporal y lo reemplaza atómicamente."""
    temporal = salida.with_suffix(".tmp")
    temporal.unlink(missing_ok=True)
    con = sqlite3.connect(temporal)
    try:
        resumen = construir(con, directorio)
    finally:
        con.close()
    temporal.replace(salida)
    return resumen


class ListasNegras:
    def __init__(self, con: sqlite3.Connection):
        self._con = con
        self._lock = threading.Lock()

    @classmethod
    def desde_directorio(cls, directorio: Path | str | None = None) -> "ListasNegras":
        directorio = Path(directorio or os.environ.get("LISTAS_DIR", "data/listas"))
        indice = directorio / "listas.sqlite"
        if indice.is_file():
            # Solo lectura e inmutable: la API nunca escribe en las listas.
            con = sqlite3.connect(f"file:{indice}?mode=ro&immutable=1", uri=True,
                                  check_same_thread=False)
            return cls(con)
        con = sqlite3.connect(":memory:", check_same_thread=False)
        if directorio.is_dir():
            construir(con, directorio)
        else:
            con.executescript(ESQUEMA)
        return cls(con)

    def _uno(self, sql: str, *args):
        with self._lock:
            return self._con.execute(sql, args).fetchone()

    @property
    def fuentes(self) -> dict[str, int]:
        with self._lock:
            return dict(self._con.execute("SELECT nombre, entradas FROM fuentes").fetchall())

    @property
    def vacia(self) -> bool:
        return not self._uno("SELECT 1 FROM urls LIMIT 1") and not self._uno(
            "SELECT 1 FROM dominios LIMIT 1")

    def popularidad(self, registrable: str) -> int | None:
        fila = self._uno("SELECT rango FROM populares WHERE dominio = ?", registrable)
        return fila[0] if fila else None

    def es_popular(self, registrable: str) -> bool:
        rango = self.popularidad(registrable)
        return rango is not None and rango <= TOP_POPULARES

    def consultar(self, url: str) -> str | None:
        """'url', 'dominio' o None."""
        clave = clave_url(url)
        if clave is None:
            return None
        if self._uno("SELECT 1 FROM urls WHERE clave = ?", clave):
            return "url"
        p = partes_host(clave)
        if p.registrable in PLATAFORMAS_COMPARTIDAS or self.es_popular(p.registrable):
            return None
        if self._uno("SELECT 1 FROM hosts WHERE host = ?", p.host) or self._uno(
            "SELECT 1 FROM dominios WHERE dominio IN (?, ?)", p.host, p.registrable
        ):
            return "dominio"
        return None
