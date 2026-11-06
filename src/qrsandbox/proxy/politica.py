"""Política de egreso anti-SSRF: ¿puede el worker conectarse a esta IP:puerto?

Regla central: solo se permiten IPs **globales** (enrutables en internet). Así se
bloquea todo lo que el atacante podría querer alcanzar desde el sandbox:
- loopback (127.0.0.0/8, ::1): servicios del propio proxy/host.
- privadas RFC 1918 (10/8, 172.16/12, 192.168/16) y ULA IPv6 (fc00::/7): red interna.
- link-local (169.254/16, fe80::/10): incluye 169.254.169.254, metadatos de la nube.
- CGNAT (100.64/10), "this network" (0/8), reservadas, documentación, benchmark...
- multicast y broadcast.
Además se "desenvuelven" las formas IPv6 que llevan una IPv4 dentro (::ffff:a.b.c.d,
6to4 2002::/16, Teredo, NAT64 64:ff9b::/96): un atacante podría usarlas para disfrazar
127.0.0.1 o 10.0.0.1 como una dirección IPv6 "global".

La decisión se toma sobre la IP YA RESUELTA, y el proxy se conecta exactamente a esa
IP (no vuelve a resolver). Eso cierra el DNS rebinding.
"""

import ipaddress

PUERTOS_PERMITIDOS = frozenset({80, 443})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")

IP = ipaddress.IPv4Address | ipaddress.IPv6Address


def _ipv4_embebidas(ip: IP) -> list[ipaddress.IPv4Address]:
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    embebidas = []
    if ip.ipv4_mapped:
        embebidas.append(ip.ipv4_mapped)
    if ip.sixtofour:
        embebidas.append(ip.sixtofour)
    if ip.teredo:
        embebidas.extend(ip.teredo)  # (servidor, cliente)
    if ip in _NAT64:
        embebidas.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return embebidas


def motivo_bloqueo_ip(ip: IP) -> str | None:
    """Devuelve el motivo del bloqueo, o None si la IP está permitida."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local_metadatos" if str(ip) == "169.254.169.254" else "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "no_especificada"
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_LOCAL:
        return "nat64_local"
    for interna in _ipv4_embebidas(ip):
        motivo = motivo_bloqueo_ip(interna)
        if motivo:
            return f"ipv6_embebida_{motivo}"
    if ip.is_private:
        return "privada"
    if not ip.is_global:
        # CGNAT 100.64/10, reservadas 240/4, 192.0.0/24, etc.
        return "no_global"
    return None


def motivo_bloqueo(ip_texto: str, puerto: int) -> str | None:
    if puerto not in PUERTOS_PERMITIDOS:
        return "puerto_no_permitido"
    try:
        ip = ipaddress.ip_address(ip_texto.split("%", 1)[0])  # quita zona IPv6 (fe80::1%eth0)
    except ValueError:
        return "ip_invalida"
    return motivo_bloqueo_ip(ip)
