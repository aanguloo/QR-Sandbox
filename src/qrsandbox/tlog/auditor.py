"""Auditor del QR Transparency Log (como los monitores de Certificate Transparency).

No confía en el servidor del log. Detecta:
- cambio de la clave del log (se fija la primera vez: TOFU) o STH con firma inválida;
- log que se achica, o dos STH del mismo tamaño con raíces distintas (bifurcación);
- STH nuevo que NO es una extensión del anterior (historial reescrito): prueba de
  consistencia inválida;
- en modo completo: hojas que no reproducen la raíz firmada, o registros sin firma
  válida del comercio;
- monitoreo: registros hechos con la clave de un comercio (¿alguien registró a mi nombre?
  ¿o yo mismo, sin saberlo, porque me robaron la clave?).

`http` es cualquier cliente con `.get(ruta, params=...)` estilo httpx (también sirve el
TestClient de FastAPI en los tests).
"""

import json

from qrsandbox.tlog import merkle
from qrsandbox.tlog.registro import Registro, mensaje_sth, verificar_firma

PAGINA = 500


def _get(http, ruta: str, **params) -> dict:
    r = http.get(ruta, params=params or None)
    r.raise_for_status()
    return r.json()


def _sth_valido(sth: dict, clave_log: str) -> bool:
    try:
        raiz = bytes.fromhex(sth["raiz"])
        msg = mensaje_sth(int(sth["tamano"]), raiz, int(sth["timestamp_ms"]))
    except (KeyError, ValueError, TypeError):
        return False
    return verificar_firma(clave_log, msg, sth["firma"])


def verificar_consistencia_sths(http, viejo: dict, nuevo: dict) -> str | None:
    """Devuelve None si `nuevo` extiende a `viejo`; si no, el motivo de la alerta."""
    m, n = viejo["tamano"], nuevo["tamano"]
    if n < m:
        return f"el log se achicó: {m} -> {n} entradas"
    if n == m:
        if viejo["raiz"] != nuevo["raiz"]:
            return f"bifurcación: dos raíces distintas para el tamaño {n}"
        return None
    if m == 0:
        return None
    prueba = _get(http, "/log/prueba-consistencia", primero=m, segundo=n)
    ruta = [bytes.fromhex(h) for h in prueba["ruta"]]
    ok = merkle.verificar_consistencia(
        m, n, bytes.fromhex(viejo["raiz"]), bytes.fromhex(nuevo["raiz"]), ruta
    )
    return None if ok else f"historial reescrito: el STH de tamaño {n} no extiende al de {m}"


def auditar(http, estado: dict, completo: bool = False, clave_comercio: str | None = None) -> dict:
    """Audita el log. `estado` (dict persistido por el llamador) se actualiza si todo está bien."""
    alertas: list[str] = []
    notas: list[str] = []

    clave = _get(http, "/log/clave-publica")["clave_publica"]
    fijada = estado.get("clave_log")
    if fijada and fijada != clave:
        alertas.append("la clave pública del log cambió")
    clave = fijada or clave

    sth = _get(http, "/log/sth")
    if not _sth_valido(sth, clave):
        alertas.append("STH actual con firma inválida")

    anterior = estado.get("sth")
    if not anterior and not alertas:
        notas.append("primera auditoría: se fija la clave del log y este STH (confianza inicial)")
    if anterior and not alertas:
        motivo = verificar_consistencia_sths(http, anterior, sth)
        if motivo:
            alertas.append(motivo)
        else:
            notas.append(f"consistente: {anterior['tamano']} -> {sth['tamano']} entradas")

    propias: list[int] = []
    if completo and not alertas:
        hojas, firmas_malas = [], []
        while len(hojas) < sth["tamano"]:
            pagina = _get(http, "/log/registros", desde=len(hojas), limite=PAGINA)["entradas"]
            if not pagina:
                break
            for e in pagina[: sth["tamano"] - len(hojas)]:
                datos = e["hoja"].encode()
                hojas.append(merkle.hash_hoja(datos))
                if not _registro_firmado(e["hoja"]):
                    firmas_malas.append(e["indice"])
                if clave_comercio and _clave_de(e["hoja"]) == clave_comercio:
                    propias.append(e["indice"])
        if len(hojas) != sth["tamano"] or merkle.raiz(hojas) != bytes.fromhex(sth["raiz"]):
            alertas.append("las hojas descargadas no reproducen la raíz firmada")
        if firmas_malas:
            alertas.append(f"registros sin firma válida del comercio: {firmas_malas}")
        if not alertas:
            notas.append(f"{len(hojas)} hojas recalculadas: raíz y firmas correctas")

    if not alertas:
        estado.update({"clave_log": clave, "sth": sth})
    return {"ok": not alertas, "alertas": alertas, "notas": notas, "sth": sth,
            "entradas_de_la_clave": propias}


def verificar_entre(http, tamano1: int, tamano2: int, clave_log: str) -> str | None:
    """Verifica la consistencia entre dos STH históricos firmados (None = todo bien)."""
    viejo = _get(http, f"/log/sth/{tamano1}")
    nuevo = _get(http, f"/log/sth/{tamano2}")
    for s in (viejo, nuevo):
        if not _sth_valido(s, clave_log):
            return f"STH de tamaño {s.get('tamano')} con firma inválida"
    return verificar_consistencia_sths(http, viejo, nuevo)


def _registro_firmado(hoja: str) -> bool:
    try:
        d = json.loads(hoja)
        r = Registro.model_validate(d["registro"])
        return verificar_firma(r.clave_publica, r.canonico(), d["firma"])
    except Exception:  # noqa: BLE001 - cualquier hoja ilegible cuenta como inválida
        return False


def _clave_de(hoja: str) -> str | None:
    try:
        return json.loads(hoja)["registro"]["clave_publica"]
    except (ValueError, KeyError, TypeError):
        return None
