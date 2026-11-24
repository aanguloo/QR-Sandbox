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

## Probar solo en tu computador (`make up`)

Si la demo pública falla (por ejemplo, el túnel de Cloudflare no entrega una URL), puedes
levantar todo localmente, sin internet de por medio ni código de acceso:

```bash
make up
```

Cuando la terminal muestre la respuesta de `/health`, abre <http://127.0.0.1:8000> en el
navegador del mismo computador. Para ver los logs usa `make logs` y para apagarlo `make down`.

Sin `make`, el equivalente es:

```bash
docker build -t qrsandbox-worker:dev -f docker/worker/Dockerfile .
mkdir -p data/listas
docker compose up -d --build --wait --remove-orphans
curl http://127.0.0.1:8000/health
```

y para apagarlo, `docker compose down`.

## Si `make` no funciona

Si `make demo` falla o no tienes `make`, ejecuta a mano los mismos pasos desde la carpeta
`QR-Sandbox`:

```bash
# 1. Entorno de Python e instalación (solo la primera vez)
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'

# 2. Imagen del worker
docker build -t qrsandbox-worker:dev -f docker/worker/Dockerfile .

# 3. Demo
mkdir -p data/listas
.venv/bin/python scripts/demo.py
```

Para apagarla:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml down --remove-orphans
```

Problemas comunes:

- **`make: command not found`** o **`No module named venv` / `ensurepip`**: falta instalar
  paquetes, ejecuta `sudo apt install -y make python3.12-venv`.
- **`permission denied ... docker.sock`**: tu usuario no puede usar Docker. Ejecuta
  `sudo usermod -aG docker $USER`, cierra y vuelve a abrir la terminal.
- **`Cannot connect to the Docker daemon`**: Docker no está encendido. En Windows abre Docker
  Desktop (con la integración WSL activada para Ubuntu); en Linux, `sudo systemctl start docker`.
