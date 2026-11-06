"""Demo pública con Cloudflare Tunnel (make demo).

1. Se asegura de que .env tenga DEMO_ACCESS_CODE (si falta, genera uno aleatorio).
2. Levanta todo con docker-compose.demo.yml (túnel + código de acceso + límites estrictos).
3. Espera la URL https://<algo>.trycloudflare.com y comprueba que responda DESDE INTERNET.
4. Genera data/demo/qr-demo.png (QR de la URL, listo para la diapositiva).
Para cerrar el túnel y apagar todo: make demo-stop.
"""

import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parent.parent
ENV = RAIZ / ".env"
SALIDA = RAIZ / "data" / "demo"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml"]
URL_TUNEL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def asegurar_codigo() -> str:
    if not ENV.exists():
        ENV.write_text((RAIZ / ".env.example").read_text())
    texto = ENV.read_text()
    m = re.search(r"^DEMO_ACCESS_CODE=(.*)$", texto, re.MULTILINE)
    if m and len(m.group(1).strip()) >= 8:
        return m.group(1).strip()
    # 12 caracteres URL-safe (~72 bits): fácil de dictar, imposible de adivinar con 1 intento/min.
    codigo = secrets.token_urlsafe(9)
    linea = f"DEMO_ACCESS_CODE={codigo}"
    texto = re.sub(r"^DEMO_ACCESS_CODE=.*$", linea, texto, flags=re.MULTILINE) if m else texto + f"\n{linea}\n"
    ENV.write_text(texto)
    ENV.chmod(0o600)
    print(f"Se generó un código de acceso nuevo en .env: {codigo}")
    return codigo


def url_del_tunel(timeout_s: int = 90) -> str:
    limite = time.time() + timeout_s
    while time.time() < limite:
        logs = subprocess.run([*COMPOSE, "logs", "tunel"], check=False, cwd=RAIZ,
                              capture_output=True, text=True).stdout
        if m := URL_TUNEL.search(logs):
            return m.group(0)
        time.sleep(2)
    raise SystemExit("El túnel no entregó una URL. Revisa: docker compose -f docker-compose.yml "
                     "-f docker-compose.demo.yml logs tunel")


def esperar_publica(url: str, timeout_s: int = 90) -> None:
    """El DNS de trycloudflare tarda unos segundos en propagarse."""
    limite = time.time() + timeout_s
    while time.time() < limite:
        try:
            if httpx.get(f"{url}/health", timeout=10).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(3)
    print("AVISO: la URL todavía no responde desde aquí (puede tardar un poco más en propagarse).")


def generar_qr(url: str) -> Path:
    import segno
    from PIL import Image, ImageDraw, ImageFont

    SALIDA.mkdir(parents=True, exist_ok=True)
    solo_qr = SALIDA / "qr-solo.png"
    segno.make(url, error="m").save(solo_qr, scale=20, border=4)
    qr = Image.open(solo_qr).convert("RGB")
    lienzo = Image.new("RGB", (qr.width, qr.height + 170), "white")
    lienzo.paste(qr, (0, 0))
    dibujo = ImageDraw.Draw(lienzo)
    try:
        grande = ImageFont.truetype("DejaVuSans-Bold.ttf", 44)
        chica = ImageFont.truetype("DejaVuSans.ttf", 26)
    except OSError:
        grande = chica = ImageFont.load_default()
    for texto, fuente, y in (("Escanéame: QR-Sandbox", grande, qr.height + 10),
                             (url.removeprefix("https://"), chica, qr.height + 90)):
        ancho = dibujo.textlength(texto, font=fuente)
        dibujo.text(((lienzo.width - ancho) / 2, y), texto, fill="black", font=fuente)
    destino = SALIDA / "qr-demo.png"
    lienzo.save(destino)
    solo_qr.unlink()
    (SALIDA / "url.txt").write_text(url + "\n")
    return destino


def main() -> int:
    codigo = asegurar_codigo()
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait", "--remove-orphans"], cwd=RAIZ, check=True)
    url = url_del_tunel()
    esperar_publica(url)
    png = generar_qr(url)
    ruta_windows = subprocess.run(["wslpath", "-w", str(png)], check=False, capture_output=True,
                                  text=True).stdout.strip()
    print(f"""
  Demo pública lista
  URL:     {url}
  Código:  {codigo}      (dilo en voz alta o muéstralo aparte: NO lo pongas en la diapositiva)
  QR:      {png}
           {ruta_windows}

  Límites: 5 análisis/min por persona, 20/min en total, 3 navegadores aislados a la vez.
  Para cerrar el túnel y apagar todo:  make demo-stop
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
