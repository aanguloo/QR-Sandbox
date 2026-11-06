#!/usr/bin/env bash
# Descarga diaria de listas para el Experimento 1. La llama la tarea programada de Windows
# "QR-Sandbox descarga diaria" (wsl.exe), a las 10:00 y al iniciar sesión. Solo descarga
# si todavía no existe el snapshot de hoy, así que correrla varias veces no hace daño.
cd "$(dirname "$0")/.." || exit 1
mkdir -p data/listas
{
  echo "=== $(date '+%Y-%m-%d %H:%M:%S %Z')"
  .venv/bin/python scripts/descargar_listas.py --si-falta-hoy
} >> data/listas/descargas.log 2>&1
