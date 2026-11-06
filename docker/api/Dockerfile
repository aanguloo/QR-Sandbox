# Imagen de la API. Solo contiene la API: no incluye Docker CLI ni el socket
# (separación de privilegios: únicamente el orquestador controla Docker).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install . \
    # Usuario sin privilegios: si la API se compromete, no es root en el contenedor.
    && useradd --system --uid 10001 --no-create-home api \
    # /data será el volumen del log; Docker copia este dueño al volumen nuevo.
    && mkdir /data && chown 10001:10001 /data && chmod 700 /data

USER 10001
EXPOSE 8000

CMD ["uvicorn", "qrsandbox.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
