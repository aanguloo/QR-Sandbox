"""Fase 3: árbol de Merkle (RFC 6962/9162)."""

import pytest

from qrsandbox.tlog import merkle

# Vectores de prueba de Certificate Transparency (certificate-transparency-go,
# merkle tree tests): datos de las hojas y raíz esperada para cada tamaño.
HOJAS_CT = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    b"\x50\x51\x52\x53\x54\x55\x56\x57",
    bytes(range(0x60, 0x70)),
]
RAICES_CT = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
HASHES_CT = [merkle.hash_hoja(d) for d in HOJAS_CT]


@pytest.mark.parametrize("n", range(1, 9))
def test_raices_coinciden_con_vectores_de_ct(n):
    assert merkle.raiz(HASHES_CT[:n]).hex() == RAICES_CT[n - 1]


def test_arbol_vacio():
    assert merkle.raiz([]).hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_ruta_de_inclusion_de_ct():
    # PATH(0, D[8]) del ejemplo de CT.
    ruta = merkle.ruta_inclusion(0, HASHES_CT)
    assert [h.hex() for h in ruta] == [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ]


def hojas(n: int) -> list[bytes]:
    return [merkle.hash_hoja(f"hoja-{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", range(1, 41))
def test_inclusion_exhaustiva(n):
    h = hojas(n)
    r = merkle.raiz(h)
    for i in range(n):
        ruta = merkle.ruta_inclusion(i, h)
        assert merkle.verificar_inclusion(i, n, h[i], ruta, r)
        # Una hoja distinta, otro índice u otra raíz no verifican.
        assert not merkle.verificar_inclusion(i, n, merkle.hash_hoja(b"falsa"), ruta, r)
        if n > 1:
            assert not merkle.verificar_inclusion((i + 1) % n, n, h[i], ruta, r)
        assert not merkle.verificar_inclusion(i, n, h[i], ruta, merkle.hash_hoja(b"x"))


@pytest.mark.parametrize("n", range(1, 41))
def test_consistencia_exhaustiva(n):
    h = hojas(n)
    rn = merkle.raiz(h)
    for m in range(1, n + 1):
        rm = merkle.raiz(h[:m])
        prueba = merkle.prueba_consistencia(m, h)
        assert merkle.verificar_consistencia(m, n, rm, rn, prueba)
        if m < n:
            # Raíz vieja falsa o raíz nueva falsa: debe fallar.
            falsa = merkle.hash_hoja(b"falsa")
            assert not merkle.verificar_consistencia(m, n, falsa, rn, prueba)
            assert not merkle.verificar_consistencia(m, n, rm, falsa, prueba)
            if prueba:
                adulterada = [falsa, *prueba[1:]]
                assert not merkle.verificar_consistencia(m, n, rm, rn, adulterada)


def test_historial_reescrito_no_es_consistente():
    """Si el log cambia una hoja vieja, ninguna prueba conecta la raíz vieja con la nueva."""
    original = hojas(10)
    reescrito = list(original)
    reescrito[3] = merkle.hash_hoja(b"hoja-3-modificada")
    r_vieja = merkle.raiz(original[:6])
    r_nueva = merkle.raiz(reescrito)
    prueba = merkle.prueba_consistencia(6, reescrito)
    assert not merkle.verificar_consistencia(6, 10, r_vieja, r_nueva, prueba)


def test_hoja_no_puede_hacerse_pasar_por_nodo():
    a, b = merkle.hash_hoja(b"a"), merkle.hash_hoja(b"b")
    # Los datos "a||b" como hoja no producen el mismo hash que el nodo (a, b).
    assert merkle.hash_hoja(a + b) != merkle.hash_nodo(a, b)


def test_parametros_invalidos():
    with pytest.raises(ValueError):
        merkle.ruta_inclusion(5, hojas(5))
    with pytest.raises(ValueError):
        merkle.prueba_consistencia(0, hojas(5))
    assert not merkle.verificar_inclusion(5, 5, b"x", [], b"y")
    assert not merkle.verificar_consistencia(6, 5, b"", b"", [])
