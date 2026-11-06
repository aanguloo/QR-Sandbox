"""Fase 2: los frames del worker se re-codifican en un proceso aislado."""

import io
import struct

import pytest
from PIL import Image

from qrsandbox.orquestador.recodificador import MAX_ALTO, MAX_ANCHO, Recodificador


def jpeg(ancho=390, alto=844, exif=False, **kw) -> bytes:
    img = Image.new("RGB", (ancho, alto), (200, 30, 30))
    salida = io.BytesIO()
    extra = {}
    if exif:
        e = Image.Exif()
        e[0x010E] = "comentario-del-atacante"  # ImageDescription
        extra["exif"] = e.tobytes()
    img.save(salida, format="JPEG", **extra, **kw)
    return salida.getvalue()


@pytest.fixture
def recod():
    with Recodificador() as r:
        yield r


def test_jpeg_valido_se_recodifica_sin_metadatos(recod):
    original = jpeg(exif=True)
    assert b"comentario-del-atacante" in original
    limpio = recod.recodificar(original)
    assert limpio is not None and limpio.startswith(b"\xff\xd8\xff")
    assert b"comentario-del-atacante" not in limpio
    assert b"Exif" not in limpio
    assert Image.open(io.BytesIO(limpio)).size == (390, 844)


def test_png_disfrazado_se_rechaza(recod):
    png = io.BytesIO()
    Image.new("RGB", (10, 10)).save(png, format="PNG")
    # Magic bytes de JPEG pegados delante de un PNG.
    assert recod.recodificar(b"\xff\xd8\xff" + png.getvalue()) is None


def test_basura_con_magic_jpeg_se_rechaza(recod):
    assert recod.recodificar(b"\xff\xd8\xff\xe0" + b"\x00" * 5000) is None


def test_dimensiones_gigantes_se_rechazan_sin_decodificar(recod):
    """Bomba de píxeles: la cabecera declara dimensiones enormes."""
    grande = jpeg(ancho=MAX_ANCHO + 1, alto=10)
    assert recod.recodificar(grande) is None
    # Cabecera SOF0 manipulada: 65000 x 65000 en un archivo diminuto.
    datos = bytearray(jpeg(ancho=16, alto=16))
    sof = datos.find(b"\xff\xc0")
    datos[sof + 5 : sof + 9] = struct.pack(">HH", 65000, 65000)
    assert recod.recodificar(bytes(datos)) is None
    assert MAX_ALTO >= 844


def test_frame_demasiado_grande_se_rechaza_antes_de_enviarlo(recod):
    assert recod.recodificar(b"\xff\xd8\xff" + b"0" * 300_000) is None


def test_si_el_hijo_muere_se_relanza(recod):
    assert recod.recodificar(jpeg()) is not None
    recod._proc.kill()  # simula un hijo que crashea (p. ej. por un exploit)
    recod._proc.wait()
    assert recod.recodificar(jpeg()) is None  # ese frame se pierde...
    assert recod.recodificar(jpeg()) is not None  # ...pero el siguiente funciona
    assert recod.reinicios >= 1


def test_el_hijo_tiene_limites_de_recursos(recod):
    recod.recodificar(jpeg())
    with open(f"/proc/{recod._proc.pid}/limits") as f:
        limites = f.read()
    assert "Max address space" in limites
    linea_as = next(ln for ln in limites.splitlines() if ln.startswith("Max address space"))
    assert "268435456" in linea_as
    linea_archivo = next(ln for ln in limites.splitlines() if ln.startswith("Max file size"))
    assert linea_archivo.split()[3] == "0"
