# QR-Sandbox — comandos del proyecto. `make help` lista los objetivos.
SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PORT  ?= 8000
# Marcador de instalación (no usar el binario: .venv/bin/python es un symlink a /usr/bin).
STAMP := $(VENV)/.instalado

.DEFAULT_GOAL := help
.PHONY: help venv dev test test-int lint seccomp build-worker up down logs ps analizar auditar clean

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

$(STAMP): pyproject.toml
	@python3 -c 'import ensurepip' 2>/dev/null || { echo 'Falta python3.12-venv: sudo apt install python3.12-venv'; exit 1; }
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e '.[dev]'
	@touch $(STAMP)

venv: $(STAMP) ## Crea .venv e instala dependencias (incluye dev)

dev: $(STAMP) ## Corre la API localmente sin Docker (solo loopback)
	$(VENV)/bin/uvicorn qrsandbox.api.main:app --host 127.0.0.1 --port $(PORT) --reload

test: $(STAMP) ## Corre los tests con pytest
	$(PY) -m pytest -q

test-int: $(STAMP) up ## Tests de integración (levanta el stack; Docker + internet)
	$(PY) -m pytest -q -m integracion

lint: $(STAMP) ## Revisa el estilo con ruff
	$(VENV)/bin/ruff check src tests

seccomp: ## Regenera el perfil seccomp del worker desde el de Docker
	python3 scripts/generar_seccomp.py

build-worker: ## Construye la imagen del worker (no es un servicio de compose)
	docker build -q -t qrsandbox-worker:dev -f docker/worker/Dockerfile .

up: build-worker ## Construye y levanta los servicios con docker compose
	docker compose up -d --build --wait
	@curl -fsS http://127.0.0.1:$(PORT)/health && echo

down: ## Apaga los servicios
	docker compose down

logs: ## Muestra los logs de los servicios
	docker compose logs -f

ps: ## Estado de los servicios
	docker compose ps

analizar: $(STAMP) up ## Analiza una URL desde la terminal: make analizar URL=https://example.com
	$(PY) -m qrsandbox.orquestador "$(URL)" --captura data/capturas/ultima.jpg

auditar: $(STAMP) ## Audita el QR Transparency Log de la API local (ARGS=--completo)
	$(PY) scripts/auditor.py $(ARGS)

clean: ## Borra .venv y cachés
	rm -rf $(VENV) .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
