# Experimentos de QR-Sandbox

Tres experimentos reproducibles. Cada uno tiene su script en una carpeta propia, deja sus
datos en `results/*.csv` y sus gráficos en `figures/`. Los comandos se corren desde la raíz
del repositorio.

| Experimento | Pregunta | Comando | Duración |
|---|---|---|---|
| 1. Detección | ¿Las señales detectan phishing que las listas negras todavía no conocen? | `make exp1` | ~1–2 h (600 URLs) |
| 2. Contención | ¿Qué logra una página hostil, o un worker comprometido, con cada perfil? | `make exp2` | ~15 min |
| 3. Sticker | ¿El log detecta QRs pegados encima de los originales? ¿Con qué error de GPS falla? | `make exp3` | ~30 s |

Ética (reglas del proyecto): las URLs maliciosas vienen solo de feeds públicos de
investigación, con como máximo 1 análisis cada 2 s, y el sandbox solo carga las páginas. Las
pruebas de contención usan solo páginas propias servidas localmente.

## 1. Detección (`exp1_deteccion/`)

1. `preparar.py` arma `dataset.csv`. Las URLs **maliciosas** son de OpenPhish y aparecen por
   primera vez en el snapshot de la fecha elegida. Las **benignas** son 50 sitios chilenos
   comunes más dominios de Tranco en los puestos 10.001–110.000.
2. `ejecutar.py` mide cuatro métodos sobre cada URL:
   - (A) solo listas negras, con snapshots **anteriores** a esa fecha (separación temporal);
   - (A\*) la lista del mismo día, como cota optimista;
   - (B) heurísticas estáticas;
   - (C) estático + dinámico, abriendo la URL en el sandbox real con gVisor.

   El script se puede retomar: salta las URLs ya medidas.
3. `analizar.py` calcula precisión, recall, F1, tasa de falsos positivos y latencia p50/p95,
   lista los falsos negativos y falsos positivos para revisarlos uno a uno, y genera los gráficos.

**Descarga diaria automática:** ejecuta una vez en PowerShell (normal, sin administrador):
`powershell -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu\home\andre\QR-Sandbox\scripts\programar_descarga.ps1`.
Crea la tarea de Windows "QR-Sandbox descarga diaria" (a las 10:00 y al iniciar sesión), que llama
a `scripts/descarga_diaria.sh` y solo descarga si falta el snapshot del día. El registro queda en
`data/listas/descargas.log`. Para quitarla:
`Unregister-ScheduledTask -TaskName "QR-Sandbox descarga diaria" -Confirm:$false`.

**Estado (6-nov):** solo hay un piloto de 8 + 8 URLs (`results/exp1_piloto_*`). La corrida
final necesita snapshots de **varios días**: hay que correr `make listas` a diario y luego
`make exp1` (por ejemplo, el 14-nov). Con un solo día, (A) no tiene lista previa y su recall
es 0 por construcción.
Hallazgo del piloto: los falsos negativos fueron sitios en `*.pages.dev` (hosting gratuito)
con nombres aleatorios. Cualquier señal nueva debe ajustarse con datos de días anteriores al
de prueba, no con el conjunto de prueba.

## 2. Contención (`exp2_contencion/`)

```bash
docker compose -f docker-compose.yml -f experiments/exp2_contencion/compose.lab.yml up -d --build --wait
.venv/bin/python experiments/exp2_contencion/ejecutar.py   # partes: escape,arranque,paginas,inundador
make up                                                     # volver al modo normal (quita el laboratorio)
```

El laboratorio (`laboratorio/servidor.py` + `paginas/`) sirve páginas hostiles propias en
`172.31.250.20:8080`. El proxy permite **solo ese ip:puerto**, y solo cuando corre con
`PROXY_LAB`, es decir, con el compose del experimento.

| Parte | Qué prueba | Resultado (6-nov) |
|---|---|---|
| B. worker comprometido (`escape.py`) | 17 intentos desde dentro del contenedor | **básico**: 9 de 17 logran su objetivo (escribir en el sistema, 1,5 GB de RAM, 1500 procesos, ~3,8 núcleos, ptrace, socket crudo, ser root, ver el kernel). **endurecido**: todo bloqueado o limitado (solo lectura, 128 MB de /tmp, OOM a ~400 MB, 255 procesos, 1 núcleo), salvo ver el kernel del anfitrión. **gVisor**: además oculta el kernel (`4.19.0-gvisor`), y al exceder la memoria o hacer una fork bomb se termina el sandbox entero (OOMKilled). `ptrace`/`unshare` funcionan, pero dentro del kernel de gVisor (no del anfitrión). Su límite de CPU es menos estricto (~1,8 núcleos). |
| C. arranque | contenedor mínimo, 10 veces | ~380 ms p50 en los tres perfiles: el costo de gVisor está en la ejecución (Chromium hace muchas syscalls), no en el arranque |
| A. páginas hostiles | 10 páginas × 3 perfiles por el pipeline real | SSRF: 21–31 intentos bloqueados por el proxy (loopback, privadas, metadatos, puertos, DNS). Memoria: sin límite llega a 1,6 GB; con límite, el renderer muere o (gVisor) se termina el sandbox. CPU e hilos: los corta el timeout de 20 s. Bucle HTTP: Chromium corta en 20 redirecciones. Descarga: bloqueada y reportada. Permisos: se detectan ubicación y notificaciones; cámara y micrófono no existen en http://. Inundación: 28 eventos visibles y el resto agrupado ("+25 dominios"). En todos los casos el contenedor se eliminó. |
| D. worker inundador | 300 mil eventos + líneas de 500 KB | el orquestador lo corta en ~0,5 s (tope de 1000 eventos), con un pico de 0,4 MB de memoria |

## 3. Sticker superpuesto (`exp3_sticker/`)

Simulación con el log real (SQLite + Merkle + firmas) de 40 QRs en dos escenarios: disperso
(4 × 4 km) y denso (300 × 300 m, como un patio de comidas). Se varía el radio registrado
(10–100 m) y el error del GPS (σ 5–80 m), y la ubicación se redondea a ~110 m como en la app.

- Con GPS normal (σ ≤ 20 m): **100 %** de stickers detectados, 100 % de QR legítimos
  verificados y 0 falsas alertas, en ambos escenarios.
- Con GPS muy impreciso (σ 80 m) en zona densa: con radio 10 m hay hasta 31 % de falsas
  alertas "no coincide". Un radio de 100 m las baja a 4 %.
- Latencia: la consulta crece de forma lineal con el tamaño del log (4 ms con 2000 entradas),
  porque se recalcula desde los datos crudos. Verificar la prueba en el cliente toma ~0,01 ms,
  con una prueba de 11 hashes (352 bytes).
