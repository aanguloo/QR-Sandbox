# Imagen del orquestador: el único componente con acceso al socket de Docker.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install ".[orquestador]"

# Corre como root DENTRO del contenedor porque el socket de Docker pertenece a
# root:root (Docker Desktop). Ojo: tener el socket ya equivale a root en el host,
# así que un usuario no root aquí no reduciría el riesgo real. Por eso este
# servicio expone solo "analizar URL" y vive en una red interna sin puertos.
EXPOSE 9000
CMD ["uvicorn", "qrsandbox.orquestador.servicio:app", "--host", "0.0.0.0", "--port", "9000"]
