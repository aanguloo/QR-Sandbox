"""Certificado TLS autofirmado para probar la web desde el celular por la red local.

    python scripts/cert_lan.py [--ip 192.168.100.7 ...] [--dir data/tls]

Por qué: la cámara (getUserMedia), WebCrypto y la geolocalización solo funcionan en un
"contexto seguro" (HTTPS o localhost). Por la red local no hay localhost, así que hace
falta HTTPS. El celular mostrará una advertencia (certificado autofirmado): es esperable
en esta prueba local. En la demo pública (Fase 8) el túnel de Cloudflare da un HTTPS real.

La clave queda legible (0644) para que el contenedor de la API (UID 10001) la lea: es un
certificado desechable, solo para la red local, válido 30 días.
"""

import argparse
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--ip", action="append", default=[])
    p.add_argument("--dir", type=Path, default=Path("data/tls"))
    args = p.parse_args()
    ips = {"127.0.0.1", *(i for i in args.ip if i)}
    clave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "QR-Sandbox (red local)")])
    ahora = datetime.now(UTC)
    sans = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    args.dir.mkdir(parents=True, exist_ok=True)
    (args.dir / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ruta_clave = args.dir / "clave.pem"
    ruta_clave.write_bytes(clave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ruta_clave.chmod(0o644)
    print(f"certificado para: localhost, {', '.join(sorted(ips))} -> {args.dir}/")


if __name__ == "__main__":
    main()
