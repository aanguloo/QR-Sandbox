# QR-Sandbox — comandos del proyecto. `make help` lista los objetivos.
SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PORT  ?= 8000
# Marcador de instalación (no usar el binario: .venv/bin/python es un symlink a /usr/bin).
STAMP := $(VENV)/.instalado

.DEFAULT_GOAL := help
.PHONY: help venv dev test test-int lint seccomp listas build-worker up lan down logs ps analizar auditar exp1 exp2 exp3 demo demo-stop clean

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

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
	$(VENV)/bin/ruff check src tests scripts experiments

seccomp: ## Regenera el perfil seccomp del worker desde el de Docker
	python3 scripts/generar_seccomp.py

build-worker: ## Construye la imagen del worker (no es un servicio de compose)
	docker build -q -t qrsandbox-worker:dev -f docker/worker/Dockerfile .

listas: $(STAMP) ## Descarga un snapshot de listas negras públicas a data/listas/
	$(PY) scripts/descargar_listas.py

up: build-worker ## Construye y levanta los servicios con docker compose
	@mkdir -p data/listas  # si no existe, Docker la crearía como root
	docker compose up -d --build --wait --remove-orphans  # quita el laboratorio del Exp. 2 si quedó
	@curl -fsS http://127.0.0.1:$(PORT)/health && echo

lan: $(STAMP) build-worker ## Como up, pero con HTTPS en la red local para el celular (puerto 8443)
	bash scripts/lan.sh

demo: $(STAMP) build-worker ## Demo pública: túnel de Cloudflare + código de acceso + QR para la diapositiva
	@mkdir -p data/listas
	$(PY) scripts/demo.py

demo-stop: ## Cierra el túnel de la demo y apaga todo
	docker compose -f docker-compose.yml -f docker-compose.demo.yml down --remove-orphans

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

exp1: $(STAMP) up ## Experimento 1 (detección): prepara el dataset, ejecuta (reanudable) y analiza
	$(PY) experiments/exp1_deteccion/preparar.py $(ARGS)
	$(PY) experiments/exp1_deteccion/ejecutar.py
	$(PY) experiments/exp1_deteccion/analizar.py

exp2: $(STAMP) build-worker ## Experimento 2 (contención): levanta el laboratorio, mide y vuelve al modo normal
	docker compose -f docker-compose.yml -f experiments/exp2_contencion/compose.lab.yml up -d --build --wait
	$(PY) experiments/exp2_contencion/ejecutar.py; $(MAKE) up

exp3: $(STAMP) ## Experimento 3 (sticker superpuesto): simulación con el log real
	$(PY) experiments/exp3_sticker/ejecutar.py

clean: ## Borra .venv y cachés
	rm -rf $(VENV) .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
