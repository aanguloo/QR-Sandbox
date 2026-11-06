# Proxy de salida anti-SSRF. Solo stdlib de Python + el módulo del proxy.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN useradd --system --uid 10001 --no-create-home egreso
WORKDIR /app
COPY src/qrsandbox/__init__.py /app/qrsandbox/__init__.py
COPY src/qrsandbox/proxy /app/qrsandbox/proxy

USER 10001
EXPOSE 3128
CMD ["python", "-m", "qrsandbox.proxy.servidor"]
