# CLAUDE.md — QR-Sandbox (anti-quishing)

Memoria del proyecto para Claude Code. La especificación completa y fuente de verdad es
[PROMPT_QR-Sandbox.md](PROMPT_QR-Sandbox.md); este archivo la resume, fija las reglas y
lleva el **estado de cada fase y las decisiones tomadas**. Mantenerlo actualizado al
cerrar cada fase.

## 1. Resumen

**Curso:** Seguridad Computacional, PUC Chile. **Entrega: jueves 19-nov-2026, 08:00.**
Se entrega código + informe de 5–10 páginas + presentación de 15 min.
Rúbrica: trabajo y resultados 35 % · profundidad técnica y de seguridad 25 % · claridad del
problema y metodología 15 % · informe y materiales 15 % · presentación 10 %.
Vale más un proceso riguroso y honesto que un resultado espectacular.

**Problema.** El quishing esquiva los filtros: la URL viaja en una imagen, se abre en el
celular (fuera del perímetro corporativo) y en el mundo físico basta un sticker sobre un QR
legítimo (parquímetros, cartas, pagos). Las listas negras llegan tarde a dominios nuevos.

**Producto.** Aplicación web (instalable como PWA). Todo lo que ve el usuario ocurre en el
navegador; no hay app nativa.

### Aporte 1 — Análisis dinámico aislado con separación de privilegios
La URL nunca se abre en el dispositivo del usuario. Un worker desechable la visita en un
sandbox endurecido y extrae señales. Ideas del curso aplicadas:
- **Separación de privilegios (OpenSSH/OKWS):** API, orquestador y worker son
  procesos/contenedores distintos. Worker = dominio sacrificable. El orquestador expone una
  interfaz estrecha (solo "analizar URL").
- **Aislamiento:** namespaces, cgroups, `--cap-drop=ALL`, seccomp, FS de solo lectura,
  usuario sin privilegios, gVisor.
- **Datos tainted (RLBox):** todo lo que devuelve el worker es no confiable y pasa por un
  validador estricto antes de usarse. El worker puede estar comprometido y mentir.
- **Anti-SSRF:** proxy de salida que bloquea IPs privadas, loopback, link-local y metadatos,
  verificando la **IP resuelta en cada conexión** (cubre redirecciones y DNS rebinding).

### Aporte 2 (innovación principal) — QR Transparency Log
Inspirado en Certificate Transparency:
- Un comercio registra cada QR físico: `{url_destino, lat, lon, radio_m, descripción,
  timestamp}` firmado con su clave **Ed25519**.
- Log **append-only con árbol de Merkle** (RFC 6962): *signed tree head*, pruebas de
  **inclusión** y **consistencia**.
- Al escanear (URL + ubicación aproximada) se responde:
  - ✅ **Verificado:** registro firmado cerca con el mismo destino (con prueba de inclusión).
  - ⚠️ **No coincide:** QR registrado cerca con otro destino → posible sticker. Alerta más fuerte.
  - ❔ **Sin registro:** solo análisis dinámico.
- Auditoría: un comercio puede monitorear QRs registrados a su nombre.
- Privacidad: ubicación redondeada (~100 m), nunca asociada a una identidad.

### Análisis en vivo
- Línea de tiempo en tiempo real ("🔀 Redirigiendo…", "🌐 Llegó a…", "🔒 Certificado…",
  "⚠️ Formulario con contraseña", "📡 Contactó N dominios", "🖼️ Marca en dominio ajeno").
- **Vista previa obligatoria** vía `Page.startScreencast` (CDP), ~2–3 fps, resolución móvil.
  Al usuario **solo le llegan imágenes**, nunca HTML/JS/recursos de la página.
- Frames = tainted (escenario JPEG malicioso de RLBox): validar magic bytes, tamaño máx.
  (~200 KB) y dimensiones; **re-codificar con Pillow en un proceso separado, sin privilegios
  y con límite de memoria**; mostrar desde `blob:` con tipo `image/jpeg` fijo. El último frame
  es la captura final. Medir latencia y ancho de banda agregados.
- Canal: el worker **no** habla con la API ni con el navegador. Escribe JSON por línea a
  stdout → el orquestador valida y publica → el navegador recibe por **SSE**
  (`GET /analisis/{id}/eventos`).

### Veredicto explicado
Combina señales y genera una explicación en lenguaje simple (sin cajas negras), con
puntaje, estado y lista de razones.

### Arquitectura
```
[Web app] --texto del QR + ubicación redondeada--> [API FastAPI]
                          |  valida, rate limit, sin acceso a Docker
                          v
                  [Orquestador] --(solo él controla Docker)--> [Worker efímero: Playwright]
                          |                                       | egress solo vía
                          |                                       v
                          |                               [Proxy de salida anti-SSRF]
                          v
[Señales estáticas] + [Señales dinámicas validadas] + [QR Transparency Log] -> [Motor de veredicto]
```

**Señales estáticas:** esquema, punycode/homoglifos, distancia de edición a marcas
(lista configurable con bancos y servicios chilenos), TLD, edad de dominio, certificado TLS
(emisor, antigüedad), acortadores, listas negras offline (snapshot descargado).
**Señales dinámicas:** cadena de redirecciones, dominio final, formularios con password,
título y marcas en el texto vs. dominio, nº de dominios de terceros, captura, tiempo de carga.

## 2. Stack y convenciones

- Python 3.12, FastAPI, Playwright (Chromium), Docker + compose, gVisor (`runsc`), SQLite,
  pytest. Frontend: HTML/CSS/JS sin framework pesado (Vite solo si hace falta), servido por
  FastAPI; jsQR (o similar) para decodificar en el navegador; WebCrypto Ed25519 en el panel
  de comercio; Leaflet + OpenStreetMap para el mapa.
- **Todo en español:** código, comentarios, documentación, mensajes.
- **Cada decisión de seguridad lleva un comentario breve** que la explique (se defiende en
  la presentación).
- Nombres de módulos sin "ñ" ni tildes (`senales`, no `señales`).

## 3. Reglas de seguridad (no negociables)

**Worker**
- Usuario sin privilegios, `--cap-drop=ALL`, `--security-opt no-new-privileges`, perfil
  seccomp, `--read-only` + `tmpfs` en `/tmp`.
- Límites: 512 MB de memoria, 1 CPU, `--pids-limit`, timeout total 20 s, siempre `--rm`.
- Red: sin acceso directo a internet ni a la red interna; **solo** a través del proxy.
- **Solo cargar páginas:** nunca enviar formularios, hacer clic en login ni escribir datos.
- Runtime configurable: `runc` por defecto, `runc` endurecido y `runsc` (gVisor). Si `runsc`
  no funciona (p. ej. WSL2), detectarlo, caer a `runc` endurecido y registrarlo.

**Separación de privilegios**
- La API **nunca** tiene acceso al socket de Docker. Solo el orquestador controla Docker.
- El worker no tiene conexión con la API ni con el navegador; solo stdout → orquestador.

**Anti-SSRF**
- Bloquear privadas (RFC 1918), loopback, link-local (incl. `169.254.169.254`), CGNAT,
  multicast, IPv6 equivalentes y metadatos de nube. Verificar la IP **resuelta en cada
  conexión**, también tras redirecciones y ante DNS rebinding.

**Datos tainted**
- Output del worker: esquema pydantic estricto (tipos, largos máximos, tamaño total, URLs
  normalizadas, esquemas permitidos). Inválido → se descarta y se cuenta.
- Eventos: `tipo` de una lista cerrada (`redireccion`, `navegacion`, `request_tercero`,
  `formulario_password`, `descarga_bloqueada`, `marca_detectada`, `captura`, `fin`, `error`).
- Anti-DoS: límite de eventos/s y totales por análisis, agrupación de repetidos
  ("+230 requests a dominios de anuncios"), límite de tamaño de frames.
- Frames: magic bytes, tamaño y dimensiones máximas, re-codificación Pillow aislada.

**Web**
- Todo texto que venga de la página analizada se inserta con `textContent`, **nunca**
  `innerHTML` (títulos de páginas maliciosas = entrada del atacante).
- CSP estricta sin scripts inline; `X-Frame-Options: DENY` + `frame-ancestors 'none'`.
- Cookies `HttpOnly` + `Secure` + `SameSite=Strict`; protección CSRF en el panel.
- Capturas desde una ruta separada con `Content-Type` fijo.
- Nunca redirigir automáticamente al destino del QR; "abrir de todas formas" con advertencia.
- La clave privada Ed25519 del comercio nunca sale del navegador.

**Demo pública (Fase 8)**
- `DEMO_ACCESS_CODE` obligatorio para lanzar análisis (evita proxy abierto contra terceros).
- Rate limit estricto (~5 análisis/min por cliente) y máx. ~3 workers concurrentes.

**Privacidad**
- Ubicación redondeada (~100 m), sin asociarla a identidad. No guardar datos personales.

## 4. Reglas éticas (obligatorias)

1. El worker solo carga páginas: nunca envía formularios, credenciales ni datos.
2. Solo URLs de feeds públicos de investigación, con rate limiting (máx. 1 análisis cada 2 s)
   y sin repetir análisis innecesariamente.
3. Las pruebas de contención se hacen **solo** contra infraestructura propia y local.
4. No poner QRs en lugares públicos ni suplantar instituciones o personas reales.
5. No guardar datos personales; las capturas de phishing se guardan solo para el análisis.

## 5. Modelo de amenaza (resumen)

- **Adversario A (remoto):** controla la página destino: contenido hostil, SSRF, agotamiento
  de recursos, cloaking, exploits contra el navegador del worker.
- **Adversario B (físico):** pega un QR falso sobre uno legítimo.
- **Adversario C (contra el log):** registra QRs a nombre de otro o reescribe el historial.
- **Fuera de alcance:** 0-day en el kernel o en gVisor (riesgo residual: kernel/KVM en el
  TCB), dispositivos del usuario comprometidos, identidad legal de quien registra (el log
  prueba posesión de clave, no identidad, como un certificado DV).

Se desarrolla en `docs/modelo-de-amenaza.md` (Fase 7).

## 6. Cómo trabajamos

- Una fase por sesión ("Continúa con la Fase N según CLAUDE.md").
- **Antes de programar cada fase:** plan corto (archivos a crear/modificar y cómo se verifica).
- Tests junto con el código, y se corren. **Una fase no está terminada si fallan.**
- Al cerrar una fase: actualizar la tabla de estado y la sección de decisiones.
- Si algo no alcanza por tiempo: avisar y proponer un recorte honesto, documentado en
  limitaciones.

## 7. Estructura del repo

```
CLAUDE.md, README.md, PROMPT_QR-Sandbox.md (especificación)
Makefile, docker-compose.yml, pyproject.toml, .env.example
src/qrsandbox/
  api/          API FastAPI (sin acceso a Docker)
  orquestador/  único que controla Docker: ejecutor (perfiles), lector + filtro (tainted,
                anti-DoS), recodificador (frames en proceso aislado), seccomp_worker.json
  worker/       Playwright; solo carga páginas; eventos JSON por stdout
  proxy/        proxy de salida anti-SSRF (politica.py = reglas de IP, servidor.py)
  tlog/         QR Transparency Log (Merkle, Ed25519, pruebas)
  senales/      señales estáticas
  veredicto/    motor de veredicto + explicación
  comun/        esquemas pydantic compartidos
docker/<componente>/Dockerfile   una imagen por componente
web/static/     frontend (Fase 5)
tests/          pytest
experiments/    scripts + results/*.csv + figures/ (Fase 6)
docs/           modelo de amenaza, diagramas, informe (Fase 7)
scripts/        utilidades (auditor del log, demo, etc.)
```

## 8. Comandos

`make help` lista todo. Principales: `make test` (unitarios), `make test-int` (integración:
Docker + internet), `make lint`, `make dev` (API local sin Docker), `make build-worker`,
`make analizar URL=...` (CLI del orquestador, guarda `data/capturas/ultima.jpg`),
`make seccomp` (regenera el perfil seccomp del worker),
`make up` / `make down` / `make logs` / `make ps` (docker compose).

## 9. Plan de fases y estado

Hoy (inicio): viernes 6-nov-2026. Entrega: jueves 19-nov-2026 08:00.

| Fase | Contenido | Aceptación | Fecha objetivo | Estado |
|---|---|---|---|---|
| 0 | Base: CLAUDE.md, estructura, compose, Makefile, README, `/health` | `make up` levanta la API y `/health` responde | vie 6-nov | ✅ 6-nov |
| 1 | Worker Playwright + orquestador (1 contenedor por análisis) | `https://example.com` → JSON válido; el contenedor desaparece | sáb 7-nov | ✅ 6-nov (adelantada) |
| 2 | Endurecimiento + proxy anti-SSRF + validación tainted + eventos | 127.0.0.1, 169.254.169.254, 10.0.0.1 y redirección a IP privada bloqueados; JSON malformado/gigante rechazado | dom 8 – lun 9-nov | ✅ 6-nov (adelantada) |
| 3 | QR Transparency Log (Merkle RFC 6962, Ed25519, endpoints, auditor) | tests de inclusión/consistencia; firma inválida rechazada; hoja alterada en BD hace fallar la verificación | mar 10 – mié 11-nov | pendiente |
| 4 | Señales estáticas + motor de veredicto + explicación | test unitario por señal; veredicto con puntaje, estado y razones | jue 12-nov | pendiente |
| 5 | Web app: Escanear, Resultado (en vivo), Comercio, Explorador del log | 4 secciones en el celular por red local; test de `<title>` con `<script>` mostrado como texto | vie 13 – sáb 14-nov | pendiente |
| 6 | Experimentos: detección, contención, sticker superpuesto + gráficos | scripts reproducibles, `results/*.csv`, `figures/` | dom 15 – lun 16-nov | pendiente |
| 7 | Materiales: README, modelo de amenaza, diagramas, borrador de informe | documentos completos | mar 17-nov | pendiente |
| 8 | Demo Cloudflare Tunnel, código de acceso, fallback gVisor, video | desde un celular con datos móviles: URL → código → escanear → análisis en vivo | mar 17 – mié 18-nov | pendiente |
| — | Holgura, ensayo de la presentación, revisión final | — | mié 18-nov | — |

**Riesgos de calendario**
- ~~gVisor en WSL2~~ resuelto el 6-nov: `runsc` funciona sobre Docker Engine nativo en WSL2.
  El fallback a `runc` endurecido se implementa igual (Fase 2/8) por si falla en la demo.
- URLs de feeds de phishing caen rápido → recolectar el dataset temprano (idealmente durante la Fase 4).
- **Recortes posibles si falta tiempo:** Exp. 1 con ~300+300 URLs; screencast a menor fps;
  explorador del log con verificación de consistencia simplificada.

## 10. Decisiones tomadas

- **(F0)** Un solo paquete Python `qrsandbox` con subpaquetes por componente; un Dockerfile
  por componente en `docker/` para que cada imagen tenga solo lo suyo (menor superficie).
- **(F0)** La API no monta `/var/run/docker.sock` (equivale a root en el host).
- **(F0)** Compose publica en `127.0.0.1` por defecto; `API_BIND=0.0.0.0` se habilita
  explícitamente para pruebas por red local (Fase 5).
- **(F0)** El contenedor de la API también va endurecido: UID 10001, `read_only`, `tmpfs /tmp`,
  `cap_drop: ALL`, `no-new-privileges`.
- **(F0)** Swagger/ReDoc desactivados (`docs_url=None`): no exponer UI con scripts de CDN en
  un servicio que se publicará por túnel.
- **(F0)** `PROMPT_QR-Sandbox.md` queda en la raíz como especificación; `*:Zone.Identifier`
  ignorado en git.
- **(F1)** El orquestador usa el **SDK de Docker** (no la CLI) y es el único que lo importa.
  `ResultadoAnalisis` vive en `comun/esquemas.py` para que la API no dependa del SDK.
- **(F1)** Orquestador = servicio interno (`POST /analizar`) en la red compose `interna`
  (`internal: true`, sin puertos publicados); la API está en `publica` + `interna`.
  Corre como root dentro de su contenedor porque el socket es `root:root`; tener el socket
  ya equivale a root en el host, así que un UID distinto no reduce el riesgo real. Mitigación:
  interfaz estrecha + red interna. Se discute como riesgo residual en el informe.
- **(F1)** Los workers no son servicios de compose: `make build-worker` construye la imagen y el
  orquestador crea un contenedor por análisis (etiqueta `qrsandbox.worker`). No se usa
  `auto_remove` (habría carrera al leer los logs): se borra siempre en un `finally`, se verifica
  que ya no exista (`contenedor_eliminado`) y al arrancar se limpian huérfanos por etiqueta.
- **(F1)** El worker es standalone (solo stdlib + Playwright); su imagen no contiene el resto
  del paquete. Chromium *headless shell* con `--no-sandbox` (default de Playwright): el sandbox
  propio de Chromium requiere userns/SUID; el aislamiento lo da el contenedor/runtime.
- **(F1)** Esquema cerrado de eventos ya en Fase 1 (unión discriminada, `extra=forbid`,
  `strict`, largos máximos, solo URLs http/https) + `LectorEventos` con topes por línea,
  totales y nº de eventos; si se exceden, el orquestador mata el worker. La Fase 2 agrega
  normalización de URLs, re-codificación de frames con Pillow y más tests hostiles.
- **(F1)** Ya en Fase 1 el worker corre con UID 10001, `cap_drop ALL`, `no-new-privileges`,
  `read_only` + tmpfs `/tmp`, 512 MB sin swap, 1 CPU, `pids_limit 256` y timeout de 20 s.
  Falta para Fase 2: seccomp propio, red sin salida salvo proxy, runtime `runsc`.
- **(F2)** Perfiles `WORKER_PERFIL`: `basico` (Docker por defecto, solo para el Exp. 2),
  `endurecido` (runc + flags + seccomp propio) y `gvisor` (endurecido + `runsc`, **por
  defecto**). Si `runsc` no aparece en `docker info` o falla al crear el contenedor, se usa
  `endurecido` y queda en `aviso_runtime`. `WORKER_RUNTIME` se reemplazó por `WORKER_PERFIL`.
- **(F2)** Red: todos los perfiles usan la red `qrsandbox_sandbox` (`internal: true`,
  172.31.250.0/24) donde solo están el proxy (IP fija 172.31.250.2, sin depender del DNS de
  Docker, que no es fiable con gVisor) y los workers. El proxy además está en `egreso`.
  **Hallazgo:** aun siendo `internal`, un contenedor de esa red llegaba a servicios del host en
  `0.0.0.0` vía el gateway 172.31.250.1 (con runc y con runsc). Se cerró con
  `com.docker.network.bridge.inhibit_ipv4=true` (el host no tiene IP en ese bridge).
  Riesgo residual: workers concurrentes comparten la red (no escuchan puertos).
- **(F2)** Proxy anti-SSRF propio (asyncio, solo stdlib): resuelve una vez, bloquea si
  *alguna* IP resuelta no es global (incluye IPv6 con IPv4 embebida: mapped, 6to4, Teredo,
  NAT64), solo puertos 80/443, y conecta a la IP validada (anti DNS rebinding). En HTTP
  plano fuerza `Connection: close` para atar la conexión a un destino. Log JSON por decisión.
  Chromium usa `bypass "<-loopback>"` para que ni 127.0.0.1 se salte el proxy, y WebRTC sin
  UDP directo. El worker **falla cerrado** sin `QRS_PROXY`.
- **(F2)** Seccomp = perfil por defecto de Docker (copia en `docker/worker/seccomp/`) menos 20
  syscalls (ptrace, process_vm_*, userfaultfd, bpf, perf_event_open, io_uring_*, keyctl,
  name_to_handle_at, …); generado por `scripts/generar_seccomp.py`. **Verificado:** con
  `runsc` el perfil seccomp OCI se ignora (`ptrace` devuelve 0 dentro de gVisor), porque las
  syscalls las atiende el Sentry (kernel de gVisor en espacio de usuario) y no el kernel del
  host; gVisor aplica su propio filtro seccomp al Sentry. Son capas alternativas, no sumadas.
- **(F2)** Frames: el worker emite screencast CDP (~2,5 fps, máx. 200 KB) + captura final. El
  orquestador valida base64/magic/tamaño y re-codifica cada frame en un **proceso hijo
  persistente** (no uno por frame) que baja a `nobody` sin grupos, con rlimit de 256 MB de
  memoria virtual, CPU, sin archivos ni procesos, timeout por frame y relanzamiento si muere.
  Para eso el orquestador tiene `cap_add: SETUID, SETGID, KILL` (ya es root vía el socket).
  Desde el host (CLI, sin root) el hijo no puede bajar de privilegios: `recodificador_aislado`
  lo indica en las métricas.
- **(F2)** Filtro anti-DoS con el reloj del orquestador: 50 eventos/s (ráfaga 100), tope por
  tipo con agrupación del excedente (`agrupados`), ≤ 4 frames/s; `fin` nunca se descarta.
- **(F2)** URLs normalizadas (esquema/host en minúsculas, IDN → punycode, sin puerto por
  defecto ni fragmento; se conserva el userinfo como señal). Se rechazan espacios/control.
- **(F2)** `ejecutar(..., al_evento=...)` publica cada evento aceptado al instante: es el
  gancho para el SSE de la Fase 5.
- **(F2)** Para los tests de redirección externa se usa `httpbin.dev` (httpbin.org y
  httpbingo.org responden 403 a `redirect-to` hacia IPs privadas).
- **(F1)** Terceros = dominio distinto al de la página actual, con aproximación "últimas 2
  etiquetas" (sin Public Suffix List). Simplificación documentada.
- **(F1)** Capturas en memoria en la API (LRU de 50) y servidas en
  `/analisis/{id}/captura` como `image/jpeg` + `nosniff`. Persistencia en SQLite más adelante.
  Nota: la especificación dice `image/png` para capturas; usamos JPEG en todo el pipeline
  (screencast y captura final) para tener un solo formato que validar.
- **(F1)** Motor Docker: **Docker Engine nativo en la distro Ubuntu de WSL2** (no Docker Desktop),
  porque Docker Desktop corre el daemon en su propia VM y no permite registrar `runsc`.
  gVisor instalado desde su repo apt + `runsc install` (`/etc/docker/daemon.json`).
  El socket ahora es `root:docker`.

## 11. Registro de estado

- **6-nov — Fase 0:** creada la estructura, `pyproject.toml`, API con `/health`, test
  `tests/test_health.py`, Dockerfile de la API, `docker-compose.yml`, `Makefile`, README.
  Tras instalar `python3.12-venv` y activar Docker en WSL: `make test` y `make lint` OK,
  `make up` deja la API *healthy* y `/health` responde → **✅**. Arreglado un bug del
  Makefile (`touch` sobre el symlink `.venv/bin/python`; ahora usa `.venv/.instalado`).
- **6-nov — Fase 1:** worker Playwright (`worker/__main__.py`), esquema de eventos
  (`comun/esquemas.py`), lector tainted (`orquestador/lector.py`), ejecutor Docker
  (`orquestador/ejecutor.py`), servicio interno + CLI del orquestador, `POST /analisis` y
  `GET /analisis/{id}/captura` en la API, compose con redes `publica`/`interna`.
  Verificación: `make test` 19 passed; `make test-int` 2 passed (example.com → título
  "Example Domain", HTTP 200, captura JPEG, 0 contenedores restantes; dominio inexistente →
  error controlado). De punta a punta por compose: `POST /analisis` OK en ~3,4 s, captura
  `image/jpeg` 34 KB, orquestador inaccesible desde el host. `http://github.com` → evento de
  redirección a https y 2 dominios de terceros. Imagen del worker: 1,27 GB.
- **6-nov — gVisor:** cambio a Docker Engine nativo en WSL2 + `runsc`. `docker run
  --runtime=runsc alpine dmesg` muestra "Starting gVisor...". `make test-int` pasa con
  `WORKER_RUNTIME=runc` y `=runsc`; compose con `runsc` OK de punta a punta. Primer dato de
  overhead (1 análisis de example.com, no es una medición): runc ~3,1 s vs runsc ~4,3–4,6 s.
- **6-nov — Fase 2:** proxy anti-SSRF (`proxy/politica.py`, `proxy/servidor.py`) en su
  contenedor, red `sandbox` aislada, perfiles basico/endurecido/gvisor con fallback, seccomp
  propio, screencast CDP + re-codificación aislada con Pillow, filtro anti-DoS, URLs
  normalizadas. Verificación: `make test` **88 passed** (política de IPs, proxy en proceso
  con DNS simulado: 127.0.0.1, 169.254.169.254, 10.0.0.1, localhost, rebinding, registro
  mixto, IPv6 embebida, CONNECT, redirección→privada, cabeceras gigantes; re-codificador con
  EXIF, PNG disfrazado, bomba de píxeles, hijo que muere; ejecutor con Docker falso: salida
  gigante → se mata y borra, JSON roto descartado, fallback de runsc). `make test-int`
  **22 passed** (los 6 casos SSRF con `endurecido` y `gvisor`, registrados como bloqueados
  en el log del proxy; sin salida directa ni acceso al host desde `sandbox`; ptrace permitido
  con el seccomp de Docker y bloqueado con el nuestro, e ignorado con runsc; los 3 perfiles analizan example.com;
  worker sin proxy no navega; re-codificador como UID 65534 sin grupos y sin acceso al socket).
  Muestra (2 corridas, example.com, no es medición): basico ~3,0 s, endurecido ~3,2 s,
  gvisor ~4,4 s; arranque del contenedor ~200 ms; re-codificación ~20–27 ms/frame.
