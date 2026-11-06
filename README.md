# QR-Sandbox

Detector de *quishing* (phishing mediante códigos QR) para el proyecto final de
Seguridad Computacional (PUC Chile). La URL de un QR nunca se abre en el
dispositivo del usuario: se analiza en un sandbox desechable y se contrasta con
un **QR Transparency Log** (inspirado en Certificate Transparency) para detectar
stickers superpuestos sobre QRs legítimos.

> Estado: Fases 0–5 y 8 terminadas; Fase 6 (experimentos) casi lista y Fase 7 (informe) pendiente: sandbox endurecido con gVisor
> y anti-SSRF, QR Transparency Log con revocación, señales y veredicto explicado, aplicación web
> con análisis en vivo, fotos paso a paso y ayuda. Ver [CLAUDE.md](CLAUDE.md) para el diseño, las reglas de
> seguridad y el plan de fases. La especificación completa está en
> [PROMPT_QR-Sandbox.md](PROMPT_QR-Sandbox.md).

## Requisitos

- Python 3.12 con `venv` (`sudo apt install python3.12-venv` en Ubuntu/WSL)
- Docker Engine + docker compose instalados **dentro de Ubuntu (WSL2)**, con el runtime
  `runsc` de gVisor (no Docker Desktop: no permite registrar gVisor; ver CLAUDE.md)
- `make`

## Probar en el celular (red local)

La cámara, la ubicación y la firma del panel de comercio solo funcionan con **HTTPS**, así
que para usar la app desde el celular hay que levantarla en "modo red local" (`make lan`),
que usa HTTPS en el puerto **8443** con un certificado propio.

### Cada vez que quieras probar

1. En la terminal de Ubuntu (WSL):
   ```bash
   cd ~/QR-Sandbox && make lan
   ```
   Al final muestra la **IP de WSL** (dentro de `connectaddress=...`) y los comandos de Windows.
2. **¿Reiniciaste Windows desde la última vez?** La IP de WSL cambia al reiniciar. En
   PowerShell revisa a dónde apunta el reenvío actual:
   ```powershell
   netsh interface portproxy show v4tov4
   ```
   Si la dirección de la columna "Conectar a" no es la que mostró `make lan`, actualízala
   (PowerShell **como administrador**; reemplaza `<IP de WSL>`):
   ```powershell
   netsh interface portproxy delete v4tov4 listenport=8443 listenaddress=0.0.0.0
   netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=8443 connectaddress=<IP de WSL>
   ```
3. En el celular, **conectado a la misma Wi-Fi** que el notebook (no con datos móviles), abre:
   ```
   https://192.168.100.7:8443
   ```
   Aparecerá una advertencia de certificado: toca **Avanzado → Continuar**. Es esperable,
   porque el certificado es propio de la red local.

`192.168.100.7` es la IP del notebook en la Wi-Fi de la casa. Si cambias de red o el router
le asigna otra, búscala en PowerShell con `ipconfig`, en "Adaptador de LAN inalámbrica
Wi-Fi" → "Dirección IPv4". `make lan` también la lista entre las "candidatas".

### Solo la primera vez (ya está hecho en este notebook)

En PowerShell **como administrador** (clic derecho → "Ejecutar como administrador"):
```powershell
# 1. Marcar la Wi-Fi de la casa como red privada (si no, el firewall bloquea al celular)
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
# 2. Reenviar el puerto 8443 de Windows a WSL (WSL2 está en modo NAT)
netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=8443 connectaddress=<IP de WSL>
# 3. Permitir el puerto en el firewall
New-NetFirewallRule -DisplayName QR-Sandbox-LAN -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
```

### Si el celular no carga la página

| Lo que pasa | Qué revisar |
|---|---|
| Se queda cargando hasta agotar el tiempo | Firewall: `Get-NetConnectionProfile` debe decir `Private`, y la regla `QR-Sandbox-LAN` debe existir (`Get-NetFirewallRule -DisplayName QR-Sandbox-LAN`). También revisa que el antivirus no tenga su propio firewall. |
| "No se puede acceder al sitio" | El reenvío apunta a una IP vieja de WSL (paso 2), o `make lan` no está corriendo: en el notebook, `https://127.0.0.1:8443` debe abrir. |
| Nada funciona | El celular debe estar en la misma Wi-Fi, sin VPN, y la IP del notebook debe ser la correcta (`ipconfig`). |
| La cámara o "Crear clave" no funcionan | La URL debe empezar con `https://`. |

Para revisar desde el notebook que todo responde:
```powershell
Test-NetConnection 192.168.100.7 -Port 8443   # debe decir TcpTestSucceeded : True
```

### Volver al modo normal y deshacer

```bash
make up      # vuelve a http://127.0.0.1:8000, solo en el notebook (el celular ya no entra)
make down    # o apaga todo
```
Para quitar los cambios de Windows (PowerShell como administrador):
```powershell
netsh interface portproxy delete v4tov4 listenport=8443 listenaddress=0.0.0.0
Remove-NetFirewallRule -DisplayName QR-Sandbox-LAN
```

### Notas

- **Qué probar:** el menú **Ayuda** dentro de la app explica cada sección (escanear, leer el
  resultado, registrar QRs como comercio, el registro público).
- No se puede "instalar la app" (PWA) en este modo, porque el navegador exige un certificado
  válido. En la demo pública (Fase 8) el túnel de Cloudflare da un HTTPS real.
- Lo que registres en el panel de comercio queda en el log (append-only). El log todavía
  tiene registros de prueba en la Plaza de Armas: si escaneas ahí, saldrá "no coincide".

## Demo pública (Cloudflare Tunnel)

```bash
make demo        # levanta todo + túnel; muestra la URL, el código de acceso y genera el QR
make demo-stop   # cierra el túnel y apaga todo
```
- Publica la app en una URL `https://<algo>.trycloudflare.com`, que **cambia cada vez**.
  `make demo` deja el QR de esa URL en `data/demo/qr-demo.png`, listo para la diapositiva.
- **Código de acceso:** sin él no se pueden lanzar análisis ni registrar QRs, así nadie puede
  usar el servicio como proxy abierto. Está en `.env` (`DEMO_ACCESS_CODE`; `make demo` lo crea
  si falta). Se ingresa una vez y queda en una cookie segura.
- **Límites:** 5 análisis por minuto por persona, 20 por minuto en total y como máximo 3
  navegadores aislados a la vez.
- Guion de la presentación, plan B y cómo grabar el video de respaldo:
  [docs/guion-demo.md](docs/guion-demo.md).

## Uso rápido

```bash
cp .env.example .env     # opcional
make test                # crea .venv, instala dependencias y corre pytest
make up                  # construye el worker, levanta API + orquestador + proxy
# Web: http://127.0.0.1:8000  (Escanear · Comercio · Log)
curl -X POST 'http://127.0.0.1:8000/analisis?esperar=true' -H 'X-QRSandbox-CSRF: 1' \
     -H 'content-type: application/json' -d '{"url":"https://example.com"}'
make lan                 # HTTPS en la red local (puerto 8443) para probar desde el celular
make analizar URL=https://example.com   # lo mismo desde la terminal, sin la API
make test-int            # tests de integración (Docker + internet)
make down
```

Sin Docker: `make dev` corre la API localmente en `http://127.0.0.1:8000`.

El perfil de aislamiento del worker se elige con `WORKER_PERFIL` en `.env`
(`gvisor` por defecto; `endurecido`; `basico` solo para comparar). gVisor requiere
Docker Engine con el runtime `runsc` (ver CLAUDE.md); si no está, se usa `endurecido`.

`make listas` descarga snapshots con fecha (OpenPhish, Phishing.Database, Tranco) y construye
el índice que la API consulta offline. Conviene correrlo una vez al día: las URLs se acumulan.
`POST /analisis` acepta `lat`/`lon` opcionales para consultar el log y devuelve un
`veredicto` con puntaje, estado y razones.

El QR Transparency Log se expone en `/log/...` y se audita con
`make auditar` (`ARGS=--completo` recalcula todo; `ARGS="--entre 1 5"` verifica la
consistencia entre dos STH firmados).

`make help` lista todos los comandos.
