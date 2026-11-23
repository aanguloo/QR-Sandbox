# QR-Sandbox

## Descargar y probar

Necesitas **Linux o Windows con WSL2** y **Docker** instalado
([cómo instalar Docker](https://docs.docker.com/engine/install/ubuntu/)). En Windows, abre la
terminal de **Ubuntu**: no funciona en PowerShell, CMD ni WSL1.

```bash
sudo apt install -y git make python3.12-venv
cd ~
git clone https://github.com/aanguloo/QR-Sandbox.git
cd QR-Sandbox
make demo
```

La primera vez tarda varios minutos. Al terminar, la terminal muestra una **URL** y un
**código de acceso**:

1. Abre la URL en el celular o en el navegador.
2. Ingresa el código de acceso.
3. Pega `https://example.com` o escanea un QR, y mira el análisis en vivo.

La URL queda accesible desde internet mientras la demo esté encendida. Para apagarla:

```bash
make demo-stop
```
