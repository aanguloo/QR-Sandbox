#!/usr/bin/env bash
# Levanta QR-Sandbox con HTTPS en la red local para probar desde el celular (make lan).
# No modifica Windows: solo IMPRIME los comandos de portproxy/firewall que hacen falta con
# WSL2 en modo NAT (deben correrse en PowerShell como administrador).
set -euo pipefail
cd "$(dirname "$0")/.."

wsl_ip=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
ps_cmd='Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -in "Dhcp","Manual" -and $_.IPAddress -notlike "169.254*" } | Select-Object -ExpandProperty IPAddress'
win_ips=$(timeout 15 powershell.exe -NoProfile -Command "$ps_cmd" 2>/dev/null | tr -d '\r' || true)

args=(--ip "$wsl_ip")
for ip in $win_ips; do args+=(--ip "$ip"); done
mkdir -p data/listas data/tls
.venv/bin/python scripts/cert_lan.py "${args[@]}"
docker compose -f docker-compose.yml -f docker-compose.lan.yml up -d --build --wait

cat <<EOF

Listo en https://127.0.0.1:8443
Para el celular (WSL2 en modo NAT), en PowerShell como ADMINISTRADOR:
  netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=8443 connectaddress=$wsl_ip
  New-NetFirewallRule -DisplayName QR-Sandbox-LAN -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
Luego, en el celular (misma Wi-Fi): https://<IP de Windows>:8443   candidatas: $(echo $win_ips)
(Acepta la advertencia del certificado autofirmado.)
Para deshacerlo:
  netsh interface portproxy delete v4tov4 listenport=8443 listenaddress=0.0.0.0
  Remove-NetFirewallRule -DisplayName QR-Sandbox-LAN
Ojo: la IP de WSL ($wsl_ip) cambia al reiniciar; si deja de funcionar, vuelve a correr make lan
y actualiza el portproxy.
EOF
