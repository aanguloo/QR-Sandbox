# QR-Sandbox

Detector de *quishing* (phishing mediante códigos QR) para el proyecto final de
Seguridad Computacional (PUC Chile). La URL de un QR nunca se abre en el
dispositivo del usuario: se analiza en un sandbox desechable y se contrasta con
un **QR Transparency Log** (inspirado en Certificate Transparency) para detectar
stickers superpuestos sobre QRs legítimos.

> Estado: Fases 0–3 (base, worker/orquestador, endurecimiento + anti-SSRF, QR Transparency Log). Ver [CLAUDE.md](CLAUDE.md) para el diseño, las reglas de
> seguridad y el plan de fases. La especificación completa está en
> [PROMPT_QR-Sandbox.md](PROMPT_QR-Sandbox.md).

## Requisitos

- Python 3.12 con `venv` (`sudo apt install python3.12-venv` en Ubuntu/WSL)
- Docker + docker compose (en WSL2: activar la integración WSL en Docker Desktop)
- `make`

## Uso rápido

```bash
cp .env.example .env     # opcional
make test                # crea .venv, instala dependencias y corre pytest
make up                  # construye el worker, levanta API + orquestador y consulta /health
curl -X POST http://127.0.0.1:8000/analisis \
     -H 'content-type: application/json' -d '{"url":"https://example.com"}'
make analizar URL=https://example.com   # lo mismo desde la terminal, sin la API
make test-int            # tests de integración (Docker + internet)
make down
```

Sin Docker: `make dev` corre la API localmente en `http://127.0.0.1:8000`.

El perfil de aislamiento del worker se elige con `WORKER_PERFIL` en `.env`
(`gvisor` por defecto; `endurecido`; `basico` solo para comparar). gVisor requiere
Docker Engine con el runtime `runsc` (ver CLAUDE.md); si no está, se usa `endurecido`.

El QR Transparency Log se expone en `/log/...` y se audita con
`make auditar` (`ARGS=--completo` recalcula todo; `ARGS="--entre 1 5"` verifica la
consistencia entre dos STH firmados).

`make help` lista todos los comandos.
