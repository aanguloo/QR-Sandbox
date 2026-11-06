"""Árbol de Merkle de Certificate Transparency (RFC 6962 / RFC 9162, sección 2.1).

- Hash de hoja: SHA-256(0x00 || datos); hash de nodo: SHA-256(0x01 || izq || der).
  Los prefijos distintos (separación de dominio) impiden hacer pasar un nodo interno
  por una hoja (ataque de segunda preimagen).
- Árbol de n hojas: se parte en k = mayor potencia de 2 menor que n.
- Prueba de inclusión: hashes hermanos desde la hoja hasta la raíz.
- Prueba de consistencia: demuestra que el árbol de tamaño m es un PREFIJO del de
  tamaño n, es decir, que el log solo agregó entradas y no reescribió el historial.

Las funciones de verificación siguen al pie de la letra los algoritmos de RFC 9162
(2.1.3.2 y 2.1.4.2): son las que también correrá el navegador en la Fase 5.
"""

import hashlib


def hash_hoja(datos: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + datos).digest()


def hash_nodo(izq: bytes, der: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + izq + der).digest()


def _division(n: int) -> int:
    """Mayor potencia de 2 estrictamente menor que n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def raiz(hojas: list[bytes]) -> bytes:
    """MTH(D[n]) a partir de los hashes de hoja."""
    n = len(hojas)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hojas[0]
    k = _division(n)
    return hash_nodo(raiz(hojas[:k]), raiz(hojas[k:]))


def ruta_inclusion(indice: int, hojas: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]): prueba de que la hoja `indice` está en el árbol de `hojas`."""
    n = len(hojas)
    if not 0 <= indice < n:
        raise ValueError("índice fuera del árbol")
    if n == 1:
        return []
    k = _division(n)
    if indice < k:
        return ruta_inclusion(indice, hojas[:k]) + [raiz(hojas[k:])]
    return ruta_inclusion(indice - k, hojas[k:]) + [raiz(hojas[:k])]


def prueba_consistencia(m: int, hojas: list[bytes]) -> list[bytes]:
    """PROOF(m, D[n]): el árbol de las primeras m hojas es prefijo del de n hojas."""
    if not 0 < m <= len(hojas):
        raise ValueError("tamaños inválidos para la prueba de consistencia")
    return _subprueba(m, hojas, True)


def _subprueba(m: int, hojas: list[bytes], completo: bool) -> list[bytes]:
    n = len(hojas)
    if m == n:
        return [] if completo else [raiz(hojas)]
    k = _division(n)
    if m <= k:
        return _subprueba(m, hojas[:k], completo) + [raiz(hojas[k:])]
    return _subprueba(m - k, hojas[k:], False) + [raiz(hojas[:k])]


def verificar_inclusion(
    indice: int, tamano: int, hoja: bytes, ruta: list[bytes], raiz_esperada: bytes
) -> bool:
    """RFC 9162, 2.1.3.2. `hoja` es el hash de hoja (no los datos crudos)."""
    if not 0 <= indice < tamano:
        return False
    fn, sn = indice, tamano - 1
    r = hoja
    for p in ruta:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = hash_nodo(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = hash_nodo(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == raiz_esperada


def verificar_consistencia(
    tamano1: int, tamano2: int, raiz1: bytes, raiz2: bytes, ruta: list[bytes]
) -> bool:
    """RFC 9162, 2.1.4.2."""
    if tamano1 > tamano2 or tamano1 < 0:
        return False
    if tamano1 == tamano2:
        return not ruta and raiz1 == raiz2
    if tamano1 == 0:
        return not ruta  # el árbol vacío es prefijo de cualquiera
    ruta = list(ruta)
    if tamano1 & (tamano1 - 1) == 0:  # potencia de 2: la raíz vieja es un nodo del árbol
        ruta.insert(0, raiz1)
    if not ruta:
        return False
    fn, sn = tamano1 - 1, tamano2 - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = ruta[0]
    for c in ruta[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = hash_nodo(c, fr)
            sr = hash_nodo(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = hash_nodo(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == raiz1 and sr == raiz2 and sn == 0
