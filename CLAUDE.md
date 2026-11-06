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
  api/          API FastAPI (sin acceso a Docker): main.py (rutas + páginas), analisis.py
                (análisis en segundo plano + SSE), seguridad.py (CSP, anti-CSRF, límite), log.py
  orquestador/  único que controla Docker: ejecutor (perfiles), lector + filtro (tainted,
                anti-DoS), recodificador (frames en proceso aislado), seccomp_worker.json
  worker/       Playwright; solo carga páginas; eventos JSON por stdout
  proxy/        proxy de salida anti-SSRF (politica.py = reglas de IP, servidor.py)
  tlog/         QR Transparency Log: merkle.py (RFC 9162), registro.py (formato canónico +
                Ed25519), log.py (SQLite append-only, STH, consulta), auditor.py
  senales/      dominio.py (PSL, homoglifos, sustituciones, marcas), marcas.json, hallazgos.py
                (tabla de PESOS), estaticas.py, dinamicas.py, listas.py, red.py (RDAP/TLS)
  veredicto/    motor.py: puntaje 0–100, estado, razones y resumen en lenguaje simple
  comun/        esquemas pydantic compartidos
docker/<componente>/Dockerfile   una imagen por componente
web/            index.html, analisis.html, comercio.html, log.html, sw.js, manifest
web/static/     css/, js/ (comun, cripto, escanear, analisis, comercio, explorador), vendor/
                (jsQR, Leaflet, qrcode-generator, con VENDOR.md), img/
tests/          pytest
experiments/    README.md, exp1_deteccion/, exp2_contencion/ (laboratorio + escape + inundador),
                exp3_sticker/, results/*.csv, figures/*.png
docs/           informe.md (+ informe.pdf), modelo-de-amenaza.md, guion-demo.md,
                diagramas/*.mmd (+ .png/.svg generados)
scripts/        utilidades (auditor del log, demo, etc.)
```

## 8. Comandos

`make help` lista todo. Principales: `make test` (unitarios), `make test-int` (integración:
Docker + internet), `make lint`, `make dev` (API local sin Docker), `make build-worker`,
`make analizar URL=...` (CLI del orquestador, guarda `data/capturas/ultima.jpg`),
`make seccomp` (regenera el perfil seccomp del worker), `make listas` (snapshot de listas
negras en `data/listas/`), `make auditar [ARGS=--completo]`
(auditor del log; también `--entre A B` y `--clave-comercio K`),
`make up` / `make down` / `make logs` / `make ps` (docker compose), `make lan` (HTTPS en la red
local, puerto 8443, para el celular; imprime los comandos de Windows necesarios),
`make exp1` / `make exp2` / `make exp3` (experimentos; ver `experiments/README.md`).

## 9. Plan de fases y estado

Hoy (inicio): viernes 6-nov-2026. Entrega: jueves 19-nov-2026 08:00.

| Fase | Contenido | Aceptación | Fecha objetivo | Estado |
|---|---|---|---|---|
| 0 | Base: CLAUDE.md, estructura, compose, Makefile, README, `/health` | `make up` levanta la API y `/health` responde | vie 6-nov | ✅ 6-nov |
| 1 | Worker Playwright + orquestador (1 contenedor por análisis) | `https://example.com` → JSON válido; el contenedor desaparece | sáb 7-nov | ✅ 6-nov (adelantada) |
| 2 | Endurecimiento + proxy anti-SSRF + validación tainted + eventos | 127.0.0.1, 169.254.169.254, 10.0.0.1 y redirección a IP privada bloqueados; JSON malformado/gigante rechazado | dom 8 – lun 9-nov | ✅ 6-nov (adelantada) |
| 3 | QR Transparency Log (Merkle RFC 6962, Ed25519, endpoints, auditor) | tests de inclusión/consistencia; firma inválida rechazada; hoja alterada en BD hace fallar la verificación | mar 10 – mié 11-nov | ✅ 6-nov (adelantada) |
| 4 | Señales estáticas + motor de veredicto + explicación | test unitario por señal; veredicto con puntaje, estado y razones | jue 12-nov | ✅ 6-nov (adelantada) |
| 5 | Web app: Escanear, Resultado (en vivo), Comercio, Explorador del log | 4 secciones en el celular por red local; test de `<title>` con `<script>` mostrado como texto | vie 13 – sáb 14-nov | 🟡 6-nov: todo listo y probado en Chromium real (móvil emulado); falta probar en un celular físico |
| 6 | Experimentos: detección, contención, sticker superpuesto + gráficos | scripts reproducibles, `results/*.csv`, `figures/` | dom 15 – lun 16-nov | 🟡 6-nov: Exp. 2 y 3 hechos; Exp. 1 con piloto, corrida final ~14-nov (necesita snapshots de varios días) |
| 7 | Materiales: README, modelo de amenaza, diagramas, borrador de informe | documentos completos | mar 17-nov | 🟡 6-nov: borrador completo (9 págs. en PDF); falta la sección del Exp. 1 (~14-nov) y la revisión del usuario |
| 8 | Demo Cloudflare Tunnel, código de acceso, fallback gVisor, video | desde un celular con datos móviles: URL → código → escanear → análisis en vivo | mar 17 – mié 18-nov | 🟡 6-nov: hecha y probada por internet (Chromium móvil emulado); falta probar con un celular real con datos móviles y grabar el video |
| — | Holgura, ensayo de la presentación, revisión final | — | mié 18-nov | — |

**Riesgos de calendario**
- ~~gVisor en WSL2~~ resuelto el 6-nov: `runsc` funciona sobre Docker Engine nativo en WSL2.
  El fallback a `runc` endurecido se implementa igual (Fase 2/8) por si falla en la demo.
- URLs de feeds de phishing caen rápido → recolectar el dataset temprano (idealmente durante la Fase 4).
- **Dataset del Exp. 1 (actualizado 6-nov):** URLhaus cerró sus descargas masivas (410, exige
  Auth-Key) y PhishTank exige registro. Fuentes usadas: OpenPhish (~300 URLs/día) y
  Phishing.Database (enlaces nuevos del día, dominios activos ~390 mil, y un archivo de enlaces
  activos de ~65 MB para muestrear). `make listas` guarda snapshots **con fecha** que se
  acumulan: correrlo cada día hasta el 15-nov. **Evitar fuga en el Exp. 1:** la lista negra
  usada en (A) debe ser un snapshot ANTERIOR a las URLs de prueba (separación temporal), si no
  la recall de (A) es 100 % por construcción. Phishing.Database tiene ruido (incluye
  gravatar.com, mercadolibre.com.ar, amazon.ie…): preferir OpenPhish como verdad de terreno.
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
- **(F3)** **Formato canónico del registro** (lo que firma el comercio y debe reproducir el
  navegador en la Fase 5): JSON con claves en orden alfabético, separadores `,` y `:` sin
  espacios, UTF-8 sin escapar no-ASCII. Campos: `clave_publica` (Ed25519 cruda, base64),
  `descripcion` (≤200, sin control), `lat_e6`/`lon_e6` (enteros, microgrados: los floats se
  serializan distinto en Python y JS), `radio_m` (5–500), `timestamp` (s Unix, ±10 min del
  servidor), `url_destino` (ya normalizada, si no se rechaza), `v="qrtlog-registro-v1"`
  (separación de dominio). Firma Ed25519 en base64. Hashes en hex.
- **(F3)** Hoja = JSON canónico de `{registro, firma, t_log_ms}`: el log compromete también el
  momento en que lo aceptó. STH firmado sobre `{v:"qrtlog-sth-v1", tamano, raiz(hex),
  timestamp_ms}`. Se firma un STH tras **cada** inserción (sin MMD) y se guarda el historial,
  así cualquier par de tamaños se puede auditar.
- **(F3)** SQLite con triggers anti UPDATE/DELETE, pero la garantía es criptográfica: pruebas y
  verificación se calculan **desde los datos crudos**, nunca desde el hash guardado. El log vive
  en el proceso de la API (volumen `datos` en `/data`, único lugar escribible; clave del log
  `0600`). Riesgo aceptado: si la API se compromete, el atacante puede firmar STHs falsos;
  eso es exactamente lo que detectan los auditores (bifurcación / historial reescrito).
- **(F3)** Consulta al escanear: ubicación redondeada a 3 decimales (~110 m) en el servidor y no
  guardada; coincidencia si distancia ≤ `radio_m` + 100 m de margen. Estados: `verificado`
  (misma URL normalizada, con prueba de inclusión), `no_coincide` (registros cercanos con otro
  destino → posible sticker), `sin_registro`. Si hay coincidencia y además otros destinos
  cercanos, gana `verificado` (dos QRs legítimos en el mismo local). Limitación: no hay
  revocación (un comercio que cambia su QR deja el viejo en el log); se discute en el informe.
- **(F3)** Duplicados (misma clave, URL, coordenadas y radio) se rechazan: evita inflar el log
  reenviando una solicitud firmada.
- **(F4)** Motor de veredicto = **suma de pesos de una tabla fija** (`senales/hallazgos.py`),
  sin ML: cada punto se rastrea a una razón. Puntaje acotado a 0–100; estados: ≥70
  `peligroso`, 35–69 `sospechoso`, <35 `sin_alertas` (no "seguro": no lo podemos garantizar).
  Cada tipo de hallazgo cuenta una vez. Resumen = "Vas a <host ASCII/punycode>: " + las 4
  frases de mayor peso. El host se muestra en ASCII para que un homoglifo no engañe en la UI.
- **(F4)** El log pesa: `no_coincide` +60 (solo, ya es `sospechoso`), `verificado` −40 (pero
  no es pase libre: un phishing evidente sigue alertando).
- **(F4)** Marcas en `senales/marcas.json` (43: bancos, servicios y courier chilenos + globales)
  con dominios legítimos y textos. Detección en el dominio, de más a menos fuerte: homoglifos
  (punycode cuyo esqueleto = marca), sustituciones (0→o, rn→m…), typosquatting (Levenshtein
  ≤1–2 según largo; desactivado para claves ≤4 letras) y nombre de la marca en un dominio
  ajeno (subcadena; solo exacta para nombres cortos como bci, sii, mach). Un hallazgo de
  marca por URL (el más fuerte). Dominio registrable con la Public Suffix List empaquetada en
  `tldextract` (offline, incluye sufijos privados como github.io).
- **(F4)** Marca en la página: cuenta si está en el **título**; en el texto visible solo si
  además hay formulario de contraseña (muchas páginas legítimas dicen "Google"). Detección de
  logos (imagen) queda fuera de alcance: se documenta. El worker ahora envía `texto_visible`
  (≤2000, tainted, solo se busca texto en él).
- **(F4)** Señales con red en la **API** (es la que tiene salida a internet), opcionales con
  `SENALES_RED=1` (compose) y timeouts de 4 s, en paralelo al sandbox. El handshake TLS va al
  host del atacante: se aplica `proxy.politica.motivo_bloqueo` a todas las IPs resueltas y se
  conecta a la IP validada (SNI = host), sin enviar HTTP. RDAP vía rdap.org. Limitación:
  RDAP no cubre `.cl` (NIC Chile no está en el bootstrap de IANA) → sin edad para `.cl`.
- **(F4)** Listas negras offline: snapshots con fecha en `data/listas/snapshots/`
  (`urls-<fuente>-<fecha>.txt` se acumulan; `dominios-…` y `tranco-…` solo el último) y un
  índice SQLite `data/listas/listas.sqlite` (44 MB; la API lo abre `mode=ro&immutable=1`,
  montado de solo lectura en `/listas`). URL exacta (+90) o mismo host / dominio listado
  (+40), salvo plataformas compartidas (vercel.app, sites.google.com…) y sitios del top 100k
  de Tranco. Medido: 75 de los ~390 mil "dominios de phishing" de Phishing.Database están en
  el top 100k de Tranco (gravatar.com #167, mercadolibre.com.ar, amazon.ie…).
- **(F4)** Popularidad (Tranco top `TOP_POPULARES`=100k): en dominios populares se omiten las
  señales de marca **débiles** (typosquatting, marca en dominio ajeno) y la de marca en la
  página; homoglifos y sustituciones se mantienen siempre (`googll.store` está en el top 5k).
  Costo aceptado: un phishing alojado en un sitio popular comprometido solo se detecta por
  URL exacta en lista negra o por señales no relacionadas con marca.
- **(F4)** Edad de dominios `.cl` vía whois de NIC Chile (`whois.nic.cl:43`; RDAP no cubre
  .cl). El dominio se valida con `fullmatch` estricto antes de enviarlo (con `match`+`$` se
  colaba un `\n` final: bug encontrado por los tests). NIC Chile limita la tasa de consultas:
  la edad de un `.cl` puede faltar a veces. Subdominios de `gob.cl` no tienen edad (no son
  registros propios en NIC).
- **(F4)** Aproximación a "muestra el logo de X": el worker reporta `imagenes` (≤40 entradas:
  `alt:`, `archivo:` nombre de archivo, `icono:` favicon; tainted). Cuenta **solo junto a un
  formulario de contraseña** (íconos sociales e insignias de tiendas son comunes en sitios
  legítimos). Reconocimiento visual del logo sigue fuera de alcance.
- **(F4)** Menciones de inicio de sesión social ("Continue with Google", "Iniciar con Apple
  ID") no cuentan como suplantación. **Falso positivo real encontrado:** github.com/login daba
  `peligroso` 75 (contraseña + "Continue with Google"); tras el arreglo, github.com/login y
  login.microsoftonline.com quedan `sin_alertas` (25: contraseña + palabra «login»).
- **(F5)** Análisis asíncrono: `POST /analisis` → 202 con un id de 128 bits (actúa como
  capacidad; `?esperar=true` responde al terminar, para scripts/experimentos). El orquestador
  transmite NDJSON (eventos validados + frames ya re-codificados + resultado) y la API re-valida
  cada línea y la publica por SSE (`/analisis/{id}/eventos`: `evento`, `estatico`, `frame`,
  `fin`, `fallo`; "error" se evitó porque choca con el evento de EventSource). Se guardan los
  eventos (≤600) para poder reconectar, pero solo el ÚLTIMO frame (un cliente lento se salta
  frames). Almacén en memoria de 200 análisis; nunca descarta uno en curso.
- **(F5)** Seguridad web (`api/seguridad.py`, middleware ASGI puro para no romper el SSE): CSP
  `default-src 'none'` + `script-src/style-src 'self'` sin inline ni eval, `img-src` solo
  propio + `blob:` + teselas OSM, `frame-ancestors 'none'` + `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy strict-origin-when-cross-origin` (OSM exige Referer; los enlaces
  al destino usan `rel=noreferrer`), Permissions-Policy, COOP/CORP. Anti-CSRF en POST:
  cabecera `X-QRSandbox-CSRF: 1` + `Content-Type: application/json` + `Origin` igual al host.
  Límite de análisis por IP (`LIMITE_ANALISIS_POR_MIN`=10, ráfaga 5) y ≤100 SSE simultáneos.
- **(F5)** Frontend sin framework ni CDN (la CSP lo impide): librerías alojadas con versión y
  sha256 en `web/static/vendor/VENDOR.md`. Todo texto externo con `el()`/`textContent`; un test
  prohíbe innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/new Function en nuestro JS
  y scripts/estilos/handlers inline en el HTML. Frames del sandbox: `Blob` con `type:
  "image/jpeg"` → `blob:` URL; la captura final desde `/analisis/{id}/captura`.
- **(F5)** `cripto.js` es espejo de `merkle.py`/`registro.py` (canónico, Ed25519 WebCrypto,
  verificación RFC 9162) y se prueba con **Node** contra vectores de Python (CT, 210 pruebas de
  inclusión y 190 de consistencia, firmas cruzadas JS↔Python). URL del registro: el navegador
  pide `POST /log/normalizar` antes de firmar (el `URL` de JS normaliza distinto).
- **(F5)** Clave del comercio: `generateKey` Ed25519 extraíble solo para permitir el respaldo; se
  guarda como CryptoKey en IndexedDB; sale del dispositivo únicamente al descargar el respaldo.
  Explorador y panel fijan la clave del log (TOFU) en localStorage y el explorador guarda el
  último STH para verificar en cada visita que el log solo creció (como un monitor de CT).
- **(F5)** **Revocación**: hoja `qrtlog-revocacion-v1` {clave_publica, indice, motivo,
  timestamp} firmada por la MISMA clave del registro; no se puede revocar dos veces, ni una
  revocación, ni algo inexistente. Los revocados no cuentan al escanear (`revocados_cercanos`
  se informa aparte). El auditor completo verifica que cada revocación sea de la clave dueña.
  Migración automática de logs anteriores (columnas `tipo`, `revoca`).
- **(F5)** **Anti-replay (hallazgo):** al probar la revocación apareció que reenviar la
  solicitud firmada original reactivaría un QR revocado. Ahora una solicitud con la misma firma
  se rechaza siempre ("registro repetido").
- **(F5)** `sin_https` solo cuenta si el destino FINAL es http (`http://github.com` redirige a
  https y daba un falso positivo).
- **(F5)** Celular por red local: cámara, WebCrypto y geolocalización exigen contexto seguro →
  `make lan` (cert autofirmado ECDSA con SAN de las IPs de WSL y Windows, 30 días, clave 0644
  por ser desechable y para que la lea el UID 10001). WSL2 está en modo NAT: hace falta un
  `netsh portproxy` + regla de firewall en Windows (el script solo los imprime). La subida de
  imagen y el pegado de enlace funcionan incluso sin HTTPS.
- **(F5)** PWA: manifest + service worker "red primero" que solo cachea la interfaz (nunca
  análisis ni datos del log).
- **(F6)** Fotos paso a paso: la API guarda hasta 8 frames clave por análisis (primero, el
  siguiente a cada navegación/redirección, uno cada 2,5 s, y la captura final), servidos en
  `/analisis/{id}/fotos/{n}` (image/jpeg, nosniff) y anunciados por SSE (`foto`). Almacén
  reducido a 100 análisis por la memoria. El cliente ignora eventos repetidos al reconectar
  (`lastEventId`).
- **(F6)** Explicaciones para no expertos en `web/static/js/explicaciones.js` (una por código de
  hallazgo; un test exige que no falte ninguna), recuadro "Qué hacer ahora", "¿Qué estoy
  viendo?" y página `/ayuda` (tutorial, sin JS).
- **(F6)** Señales nuevas: `rastreador_ip` (+40; lista de IP loggers de mejor esfuerzo en
  `senales/rastreadores.json`, se revisa cada salto de la cadena) y `permiso_sensible` (+20;
  el worker envuelve geolocalización, getUserMedia y Notification ANTES de que corra la
  página, avisa por un binding y niega; nuevo evento cerrado `permiso_solicitado`). 23 marcas
  nuevas (DocuSign, Western Union, Roblox, telcos y comercios chilenos…: 66 en total).
- **(F6)** Experimento 2: el proxy admite `PROXY_LAB=ip:puerto` (UNA excepción exacta, solo con
  el compose del experimento) para alcanzar el laboratorio local. "basico" corre como root
  (default de Docker). Pruebas destructivas en contenedores separados porque con gVisor
  exceder la memoria termina el sandbox entero. `make up` usa `--remove-orphans`.
- **(F6)** Experimento 1: veredictos calculados fuera de la API para controlar qué listas se
  usan (separación temporal: solo snapshots anteriores a la fecha de las maliciosas).
  **No ajustar señales con el conjunto de prueba.**
- **(F8)** Código de acceso (`api/acceso.py`): con `DEMO_ACCESS_CODE` definido, `POST /analisis`,
  `/log/registros` y `/log/revocaciones` exigen la cookie `qrs_acceso` (HMAC-SHA256 con un
  secreto aleatorio por arranque, vence a las 12 h, `HttpOnly; Secure; SameSite=Strict`). El
  código se compara en tiempo constante, con 5 intentos y luego 1/min por IP. Las lecturas
  siguen abiertas (el log es público). El anti-CSRF existente protege la cookie.
- **(F8)** Detrás del túnel todos llegan desde la IP de cloudflared: en modo demo la IP del
  cliente sale de `CF-Connecting-IP` (Cloudflare la sobrescribe en el borde; fuera del modo
  demo se ignora). Límites de la demo: 5/min por persona, 20/min en total, 3 análisis y 3
  workers simultáneos. HSTS cuando llega `X-Forwarded-Proto: https`.
- **(F8)** El túnel es un contenedor (`cloudflare/cloudflared:2026.10.7`, sin root, solo
  lectura, sin capabilities) en la red `publica`: solo alcanza a la API. `make demo` genera
  el código si falta, espera la URL, comprueba que responda desde internet y genera
  `data/demo/qr-demo.png` (segno + Pillow). El orquestador registra al arrancar el perfil
  efectivo del worker (fallback de gVisor visible en los logs y en `aviso_runtime`).
- **(F8)** **Hallazgo: el borde de Cloudflare (quick tunnel) retiene los primeros ~500 KB de un
  SSE** antes de dejarlo pasar: la línea de tiempo llegaba toda junta a los ~8 s. Medido y
  descartado como causa: el tipo de contenido (ahora exactamente `text/event-stream`, sin
  charset), `no-transform`/`no-cache`, un relleno de 64 KB y `--protocol http2`. Solución: el
  navegador usa SSE y, si en 2,5 s no llega nada, cambia solo a **sondeo**
  (`/analisis/{id}/progreso` cada 0,7 s + `/analisis/{id}/frame`, image/jpeg). Por el túnel, la
  línea de tiempo aparece a los ~4,7 s. En local y en la red local sigue siendo SSE.
- **(F7)** Informe en Markdown (`docs/informe.md`) con PDF generado por `scripts/informe_pdf.py`
  (Markdown → HTML → Chromium de la imagen del worker; informa el nº de páginas). Diagramas en
  Mermaid (`docs/diagramas/*.mmd`, GitHub los muestra) renderizados a PNG/SVG con
  `scripts/render_diagramas.py` (mermaid 11.4.1 en `data/herramientas/`, no versionado). En
  Python-Markdown una lista necesita una línea en blanco antes (GitHub no): el informe la tiene.
- **(F7)** Medición agregada al Exp. 2 (pedida por la especificación): costo de la vista previa
  (`costo_frames.py`): re-codificación aislada mediana 14 ms/frame (6–32), 1,6 % de la duración,
  15–390 KB de imágenes por análisis.
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
- **6-nov — Fase 3:** QR Transparency Log completo: `tlog/merkle.py`, `tlog/registro.py`,
  `tlog/log.py`, `tlog/auditor.py`, `api/log.py` (`/log/clave-publica`, `/log/sth`,
  `/log/sth/{n}`, `/log/registros` GET/POST, `/log/registros/{i}`, `/log/prueba-inclusion`,
  `/log/prueba-consistencia`, `/log/consultar`, `/log/por-clave`) y `scripts/auditor.py`.
  Verificación: `make test` **215 passed**. El árbol reproduce los vectores oficiales de CT
  (8 raíces + ruta de inclusión) y pasa pruebas exhaustivas de inclusión/consistencia para
  tamaños 1–40 con pruebas adulteradas. Aceptación: firma inválida, registro alterado tras
  firmar y suplantación de clave → rechazados; hoja modificada en la BD (quitando el trigger)
  → `verificar_integridad` falla, la prueba de inclusión no verifica contra el STH firmado y
  el auditor completo alerta (raíz y firma). El auditor además detecta log bifurcado con la
  misma clave, log que se achica y cambio de clave. Con el stack real: registro → reinicio de
  la API (persistencia OK) → `auditor.py --completo` y `--entre 1 5` OK; `/data` 0700 y la
  clave 0600. Nota: el volumen `datos` quedó con 5 registros de prueba; `docker compose down -v`
  reinicia el log (borra también la clave del log).
- **6-nov — Fase 4:** señales estáticas (`senales/estaticas.py`: esquema, `@`, IP, puerto,
  TLD, acortador, subdominios, palabras clave, homoglifos, sustitución, typosquatting, marca
  en dominio ajeno, punycode, lista negra, edad de dominio, certificado), dinámicas
  (`senales/dinamicas.py`: redirecciones, cambio de dominio, marca en página ajena,
  contraseña, descarga, terceros), motor (`veredicto/motor.py`) y `scripts/descargar_listas.py`.
  `POST /analisis` acepta `lat`/`lon` opcionales y devuelve `veredicto`, `senales_estaticas`
  y `log`. Verificación: `make test` **257 passed** (≥1 test por señal; el ejemplo de la
  especificación "Vas a login-micr0soft.xyz: usa un 0 en lugar de una o…" da `peligroso`
  100; sitios legítimos no disparan marcas; TLS no conecta a IPs internas). `make test-int`
  22 passed. Con el stack real (gVisor + RDAP + TLS): example.com y bancoestado.cl
  `sin_alertas`; una URL de OpenPhish `peligroso` 100. Bug corregido: `partes_host` no pasaba
  hosts Unicode a punycode. Los tests de `/analisis` ya no crean `data/tlog.sqlite` real.
- **6-nov — Arreglos pre-Fase 5 (pedido del usuario):** (1) fuentes de listas: OpenPhish +
  Phishing.Database + Tranco, snapshots con fecha e índice SQLite de solo lectura; (2) edad de
  `.cl` vía whois NIC Chile; (3) pistas de logos (alt/archivo/favicon) con contraseña; (4)
  filtro de popularidad contra falsos positivos de marca; (5) arreglo del falso positivo de
  login social encontrado al probar github.com/login. `make test` **275 passed**,
  `make test-int` **23 passed** (incluye whois real). Con el stack: bancoestado.cl
  `sin_alertas` con edad 9930 días (whois) y Tranco #7848; github.com/login y
  login.microsoftonline.com `sin_alertas`.
- **6-nov — Fase 5:** web completa (`/`, `/analisis/{id}`, `/comercio`, `/log`), análisis en
  vivo por SSE, seguridad web, revocación + anti-replay, `make lan`. Verificación: `make test`
  **308 passed** (incluye `cripto.js` con Node contra Python, CSP/CSRF, reglas sobre el JS/HTML,
  SSE, frames no-JPEG descartados, revocación). `make test-int` **25 passed**, entre ellos en
  **Chromium real**: (a) aceptación XSS: un `<title>` con `<script>` y `<img onerror>` y una
  URL con `<script>` se ven como texto, `window.__xss` queda indefinido, 0 imgs inyectadas, 0
  diálogos, y las 4 páginas cargan sin violaciones de CSP ni errores de JS; (b) recorrido del
  comercio: crear clave → clic en el mapa → firmar y registrar (recibo verificado en el
  navegador) → escaneo en ese lugar "✅ Verificado… comprobado en tu navegador" → explorador
  (firma del STH, inclusión, firma del comercio) → revocar → el explorador confirma solo
  "1 → 2". Con el stack real (gVisor): `http://github.com` → 14 frames en vivo + veredicto.
  Capturas en móvil emulado (Pixel 7) revisadas. **Pendiente:** probar en un celular físico
  (requiere los comandos de Windows de `make lan`). **Ojo demo:** el log real tiene 5
  registros de prueba de la Fase 3 en la Plaza de Armas (a0.cl, b0.cl…) que hacen que
  cualquier escaneo ahí salga "no coincide"; limpiar antes de la demo (`docker compose down -v`
  borra el log y su clave).
- **6-nov — Fase 6 (en curso):** pedido del usuario: fotos paso a paso, explicaciones para no
  expertos y página de ayuda; además rastreadores de IP, permisos sensibles y marcas nuevas
  (verificado con phishing real: una página falsa de DocuSign pasó a `peligroso` 100 por
  marca en dominio y en título). `make test` **320 passed**, `make test-int` **25 passed**.
  Experimentos (ver `experiments/README.md`): **Exp. 3** completo (100 % de stickers y 0 falsas
  alertas con GPS σ ≤ 20 m; zona densa + GPS σ 80 m + radio 10 m: 31 % falsas alertas; latencia
  lineal, 4 ms con 2000 entradas). **Exp. 2** completo (matriz de 17 intentos × 3 perfiles,
  páginas hostiles, arranque ~370 ms igual en los tres, worker inundador cortado en 0,5 s).
  Hallazgos: gVisor termina el sandbox entero por OOM, oculta el kernel, deja ~1,7 núcleos
  pese al límite de 1 CPU; `ptrace`/`unshare` "permitidos" pero contenidos en el Sentry.
  **Exp. 1**: scripts listos y piloto 8+8 (B y C: recall 0,5, 0 FP; los FN fueron `*.pages.dev`
  aleatorios). **Pendiente:** correr `make listas` a diario hasta ~14-nov y luego `make exp1`.
- **6-nov — Fase 8:** demo pública con Cloudflare Tunnel (`make demo` / `make demo-stop`,
  `docker-compose.demo.yml`, `scripts/demo.py`), código de acceso (`api/acceso.py` + formulario
  en Escanear y Comercio), límites por persona y globales, HSTS, registro del perfil de gVisor
  y respaldo por sondeo del canal en vivo. Verificación: `make test` **331 passed**;
  integración web 2 passed. **Por internet** (URL pública): HTTPS + HSTS + CSP, sin código
  401, código incorrecto 401, código correcto → cookie con HttpOnly/Secure/SameSite=Strict,
  análisis 202, origen ajeno 403. Chromium móvil emulado por la URL pública: formulario de
  código → análisis → línea de tiempo y vista previa a los 4,7 s, veredicto a los 13,3 s,
  5 fotos, 0 errores de JS. Guion de la demo y del video: `docs/guion-demo.md`.
  **Pendiente:** prueba con un celular real con datos móviles y grabar el video de respaldo.
- **6-nov — Fase 7 (borrador):** `docs/modelo-de-amenaza.md` (9 activos, 6 fronteras, 4
  adversarios, 18 amenazas con mitigación + archivo + evidencia, supuestos, riesgos residuales),
  3 diagramas (arquitectura con fronteras de confianza, flujo de un análisis, log de
  transparencia), `docs/informe.md` + `docs/informe.pdf` (9 páginas A4; sección 4.3 del Exp. 1
  marcada como pendiente con su diseño y el piloto) y README con reproducción desde cero
  (Docker Engine + gVisor en WSL2). Cifras corregidas con los CSV finales (arranque 366–370 ms,
  CPU básico ~3,3 y gVisor ~1,7 núcleos). **Pendiente:** completar 4.3 tras `make exp1` y que el
  usuario revise el informe.
