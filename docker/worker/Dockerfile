# Imagen del worker desechable. Solo contiene Chromium (headless shell), Playwright
# y el módulo del worker: ni la API, ni el orquestador, ni el SDK de Docker.
FROM python:3.12-slim

ARG PLAYWRIGHT_VERSION=1.64.1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    # El FS es de solo lectura en ejecución: HOME apunta al tmpfs.
    HOME=/tmp \
    PYTHONPATH=/app

RUN pip install "playwright==${PLAYWRIGHT_VERSION}" \
    && playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home worker

WORKDIR /app
COPY src/qrsandbox/__init__.py /app/qrsandbox/__init__.py
COPY src/qrsandbox/worker /app/qrsandbox/worker

USER 10001
ENTRYPOINT ["python", "-m", "qrsandbox.worker"]
