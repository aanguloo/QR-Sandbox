# Prompt para Claude — Proyecto QR-Sandbox (anti-quishing)

> Cómo usarlo: pega todo este documento en la primera sesión de Claude Code dentro de un repo vacío.
> Pídele que primero cree el `CLAUDE.md` y el plan, y luego trabaja **una fase por sesión**
> diciendo: "Continúa con la Fase N según CLAUDE.md".

---

## Rol y contexto

Eres mi compañero de ingeniería para el proyecto final del curso de Seguridad Computacional (PUC Chile).
Entrega: **19 de noviembre de 2026, 8:00 am**. Se entrega el código + un informe de 5–10 páginas + una presentación de 15 minutos.
Rúbrica: trabajo realizado y resultados 35%, profundidad técnica y de seguridad 25%, claridad del problema y la metodología 15%, informe y materiales 15%, presentación 10%.
Se valora más un proceso técnico riguroso y honesto que un resultado espectacular.

**El producto es una aplicación web** (que también se puede instalar como PWA en el celular). Todo lo que ve el usuario ocurre en el navegador; no hay app nativa.

Stack: **Python 3.12, FastAPI, Playwright (Chromium), Docker + docker compose, gVisor (runsc), SQLite, pytest**. Frontend web: HTML/CSS/JS sin framework pesado (o Vite + JS si hace falta), servido por FastAPI, con un decodificador de QR en el navegador (jsQR o similar) y WebCrypto para las firmas Ed25519 del lado del comercio.
Escribe el código, los comentarios y la documentación en **español**.

## El problema

El quishing (phishing mediante códigos QR) esquiva los filtros tradicionales: la URL va dentro de una imagen, el usuario la abre en su celular (fuera del perímetro corporativo) y, en el mundo físico, basta con pegar un sticker sobre un QR legítimo (parquímetros, cartas de restaurantes, pagos).
Las herramientas actuales solo consultan listas negras, que llegan tarde ante dominios recién creados.

## Qué construimos: QR-Sandbox, con dos aportes innovadores

### Aporte 1 — Análisis dinámico aislado con separación de privilegios
La URL de un QR **nunca se abre en el dispositivo del usuario**. Un worker desechable la visita dentro de un sandbox endurecido y extrae señales. El diseño aplica explícitamente las ideas del curso:
- **Separación de privilegios (OpenSSH/OKWS):** la API, el orquestador y el worker son procesos/contenedores distintos. El worker es un dominio sacrificable y sin privilegios; el orquestador expone una interfaz estrecha (solo "analizar URL").
- **Aislamiento (contenedores, gVisor, Firecracker):** namespaces, cgroups, `--cap-drop=ALL`, seccomp, filesystem de solo lectura, usuario sin privilegios, runtime gVisor.
- **Interfaz con datos *tainted* (RLBox):** todo lo que devuelve el worker se trata como no confiable y pasa por un validador estricto (pydantic, límites de tamaño, tipos, esquemas de URL) antes de usarse. El worker puede estar comprometido y mentir.
- **Anti-SSRF:** un proxy de salida bloquea IPs privadas, loopback, link-local y metadatos de la nube (incluso después de las redirecciones y del DNS rebinding: la verificación se hace sobre la IP resuelta en cada conexión).

### Aporte 2 (la innovación principal) — QR Transparency Log: procedencia verificable de QRs físicos
Inspirado en **Certificate Transparency**:
- Un comercio o institución **registra** cada QR físico que instala: `{url_destino, lat, lon, radio_m, descripción, timestamp}`, **firmado con su clave Ed25519**.
- Los registros se agregan a un **log append-only con árbol de Merkle**. El log publica una raíz firmada (*signed tree head*) y entrega **pruebas de inclusión** y de **consistencia**, como en CT.
- Al escanear, la app envía URL + ubicación aproximada. El sistema responde con uno de tres estados:
  - ✅ **Verificado:** existe un registro firmado cerca de esa ubicación con ese mismo destino (con prueba de inclusión).
  - ⚠️ **No coincide:** hay un QR registrado cerca, pero apunta a otro destino → **posible sticker superpuesto**. Es la alerta más fuerte.
  - ❔ **Sin registro:** se usa solo el análisis dinámico del aporte 1.
- Así, un ataque físico que es invisible para las listas negras se vuelve detectable. El log además permite auditar: un comercio puede monitorear si alguien registró QRs a su nombre.
- Privacidad: la ubicación del usuario se redondea (por ejemplo, a unos 100 m) y no se guarda asociada a ninguna identidad.

### Análisis en vivo: "qué está haciendo el link"
Mientras el sandbox analiza la URL, la web muestra **en tiempo real** lo que hace el link, como una línea de tiempo:
"🔀 Redirigiendo a `bit.ly/...`" → "🌐 Llegó a `login-micr0soft.xyz` (dominio creado hace 2 días)" → "🔒 Certificado emitido ayer" → "⚠️ Formulario que pide contraseña" → "📡 Contactó 14 dominios de terceros" → "🖼️ Muestra el logo de Microsoft en un dominio que no es de Microsoft".
**Vista previa en vivo (obligatoria):** junto a la línea de tiempo, el usuario ve lo que "ve" el navegador del sandbox, usando el screencast de Chrome DevTools Protocol (`Page.startScreencast`, a unos 2–3 fps, resolución de celular). Al usuario **solo le llegan imágenes**: nunca el HTML, los scripts ni los recursos de la página analizada, así que nada de la página se ejecuta en su navegador.
Los frames se tratan como datos tainted, siguiendo el escenario del JPEG malicioso de la clase de RLBox:
- El orquestador valida los magic bytes JPEG, un tamaño máximo por frame (por ejemplo, 200 KB) y las dimensiones máximas.
- **Re-codifica cada frame con Pillow** (decodificar → nuevo JPEG limpio sin metadatos) dentro de un proceso separado, sin privilegios y con límites de memoria. Así, si un frame intentara explotar un decoder de imágenes, el riesgo queda dentro de ese proceso aislado y no llega al navegador del usuario.
- El navegador muestra los frames en un `<img>` o `<canvas>` a partir de un `blob:` con tipo `image/jpeg` fijo.
- Al terminar, el último frame se guarda como la captura final del análisis.
- En el informe se mide el costo: latencia agregada por la re-codificación y ancho de banda por análisis.

Diseño seguro del canal en vivo (es una nueva superficie de ataque y hay que defenderla en el informe):
- **Separación de privilegios:** el worker **no** tiene conexión con la API ni con el navegador. Escribe eventos JSON (uno por línea) a su stdout; el orquestador los lee, los valida y los publica. El navegador los recibe por **Server-Sent Events** (`GET /analisis/{id}/eventos`).
- **Eventos tainted:** cada evento se valida contra un esquema cerrado (pydantic): `tipo` de una lista fija (`redireccion`, `navegacion`, `request_tercero`, `formulario_password`, `descarga_bloqueada`, `marca_detectada`, `captura`, `fin`, `error`), campos con largo máximo y URLs normalizadas. Los eventos inválidos se descartan y se cuentan.
- **Anti-DoS:** límite de eventos por segundo y de eventos totales por análisis, agrupación de eventos repetidos ("+230 requests a dominios de anuncios") y límite de tamaño para los frames del screencast.
- **Anti-XSS:** todo texto que viene de la página analizada se inserta con `textContent`, nunca con `innerHTML`.
*Esto se implementa en las Fases 1–2 (emisión y validación de eventos) y en la Fase 5 (línea de tiempo en la web).* Se agrega al Experimento 2 una página de prueba propia que genera miles de requests, para demostrar que el canal en vivo no colapsa.

### Veredicto explicado
El motor combina las señales y genera una explicación en lenguaje simple. Por ejemplo: "Vas a `login-micr0soft.xyz`: usa un 0 en lugar de una o, el dominio y el certificado tienen 2 días, pasa por 4 redirecciones y muestra un formulario de inicio de sesión con la marca Microsoft." El veredicto debe poder explicarse; nada de cajas negras.

## Arquitectura

```
[Web app en el navegador] --texto del QR + ubicación redondeada--> [API FastAPI]
                                     |  valida, rate limit, sin acceso a Docker
                                     v
                             [Orquestador] --(solo él controla Docker)--> [Worker efímero: Playwright]
                                     |                                       | egress solo vía
                                     |                                       v
                                     |                               [Proxy de salida anti-SSRF]
                                     v
     [Señales estáticas] + [Señales dinámicas validadas] + [QR Transparency Log] -> [Motor de veredicto]
```

Señales a implementar:
- **Estáticas:** esquema, punycode/homoglifos, distancia de edición a marcas conocidas (lista configurable que incluya bancos y servicios chilenos), TLD, edad del dominio cuando sea posible, datos del certificado TLS (emisor, antigüedad), acortadores, listas negras públicas (consultadas offline desde un snapshot descargado).
- **Dinámicas (desde el worker):** cadena completa de redirecciones, dominio final, presencia de formularios con campos de contraseña, título y marcas detectadas en el texto frente al dominio, cantidad de dominios de terceros contactados, captura de pantalla, tiempo de carga.

## Requisitos de seguridad del worker (no negociables)
- Usuario sin privilegios, `--cap-drop=ALL`, `--security-opt no-new-privileges`, perfil seccomp, `--read-only` + `tmpfs` en /tmp.
- Límites: memoria (512 MB), CPU (1), `--pids-limit`, timeout total de 20 s, y se destruye siempre (`--rm`).
- Red: sin acceso directo a internet ni a la red interna; solo el proxy de salida.
- **Solo cargar páginas:** nunca enviar formularios, hacer clic en botones de login ni escribir datos.
- Runtime configurable: `runc` (Docker por defecto), `runc` endurecido y `runsc` (gVisor), para poder compararlos.

## Fases (una por sesión, cada una con tests y criterios de aceptación)

**Fase 0 — Base.** Crear `CLAUDE.md` (con el resumen de este documento y las reglas de seguridad), la estructura del repo, `docker-compose.yml`, `Makefile` y un README mínimo.
*Aceptación:* `make up` levanta la API y `/health` responde.

**Fase 1 — Worker + orquestador.** Worker con Playwright que recibe una URL y devuelve JSON + captura. El orquestador lanza un contenedor por análisis.
*Aceptación:* analizar `https://example.com` devuelve un JSON válido y el contenedor desaparece al terminar.

**Fase 2 — Endurecimiento + anti-SSRF + validación *tainted*.** Aplicar los requisitos de seguridad del worker. Proxy de salida con bloqueo de rangos privados, revalidado en cada conexión. Esquema pydantic estricto para el output del worker.
*Aceptación:* los tests demuestran que `http://127.0.0.1`, `http://169.254.169.254`, `http://10.0.0.1` y una redirección hacia una IP privada quedan bloqueados. Un JSON malformado o gigante del worker se rechaza.

**Fase 3 — QR Transparency Log.** Árbol de Merkle append-only (RFC 6962 como referencia), firmas Ed25519 para registros y raíces, endpoints para registrar, consultar por ubicación, obtener pruebas de inclusión y de consistencia, más un script de auditor que verifica la consistencia entre dos raíces.
*Aceptación:* tests de inclusión y consistencia, y rechazo de registros con firma inválida. Modificar una hoja en la base de datos hace fallar la verificación.

**Fase 4 — Señales estáticas + motor de veredicto + explicación.**
*Aceptación:* tests unitarios para cada señal; el veredicto incluye un puntaje, un estado y una lista de razones legibles.

**Fase 5 — Aplicación web.** Una web responsive, usable en el celular, con cuatro secciones:
1. **Escanear (`/`):** cámara del navegador o subir una imagen/captura con el QR (sirve para QRs que llegan por correo o PDF). El QR se decodifica en el navegador y se muestra el destino **antes** de abrirlo, sin redirigir nunca automáticamente.
2. **Resultado (`/analisis/{id}`):** el estado del log (✅/⚠️/❔), el veredicto con sus razones, la captura de pantalla tomada en el sandbox, la cadena de redirecciones y un botón "abrir de todas formas" con una advertencia clara.
3. **Panel de comercio (`/comercio`):** genera el par de claves Ed25519 **en el navegador** con WebCrypto (la clave privada nunca sale del dispositivo; se puede exportar como respaldo), registra un QR con su ubicación (seleccionada en un mapa Leaflet + OpenStreetMap), firma el registro y descarga el QR listo para imprimir junto con su recibo de inclusión.
4. **Explorador del log (`/log`):** la raíz firmada actual, la lista de registros, la verificación de pruebas de inclusión y consistencia **en el navegador** (para que el usuario no tenga que confiar en el servidor) y una vista de auditoría para que un comercio vea todos los QRs registrados con su clave.
Seguridad web (clases de Seguridad Web y Top Web Attacks): CSP estricta sin scripts inline, `X-Frame-Options: DENY`/`frame-ancestors 'none'` (anti-clickjacking), cookies `HttpOnly` + `Secure` + `SameSite=Strict` si se usan, protección CSRF en el panel, escapar todo lo que viene del sandbox (títulos y textos de páginas maliciosas son entrada del atacante → riesgo de XSS) y servir las capturas con `Content-Type: image/png` desde una ruta separada.
*Aceptación:* las cuatro secciones funcionan en el celular por la red local; hay un test que demuestra que un `<title>` malicioso con `<script>` del sitio analizado se muestra como texto y no se ejecuta.

**Fase 6 — Experimentos reproducibles** (carpeta `experiments/`, cada uno con su script y un `results/*.csv`):
1. **Detección:** de 300 a 500 URLs maliciosas de feeds públicos (PhishTank/OpenPhish/URLhaus) y la misma cantidad de benignas (Tranco + sitios chilenos comunes). Comparar (A) solo listas negras, (B) solo heurísticas estáticas y (C) estático + dinámico. Medir precisión, recall, F1, falsos positivos y latencia p50/p95. Incluir un análisis cualitativo de los falsos negativos.
2. **Contención:** páginas de prueba **propias, servidas localmente**, que intentan SSRF hacia localhost y metadatos, agotar memoria/CPU, crear procesos en exceso, escribir en disco y redirigir en bucle. Correrlas con `runc` por defecto, `runc` endurecido y `runsc`. Tabla: qué se bloqueó, en qué capa y el overhead en tiempo de arranque.
3. **Sticker superpuesto (para validar la innovación):** registrar en el log de 20 a 50 QRs simulados con ubicaciones, y luego simular escaneos con el destino legítimo, con un destino distinto en la misma ubicación (sticker) y sin registro. Medir la tasa de detección de "no coincide", los falsos positivos por imprecisión del GPS (variando el radio) y la latencia de las pruebas de inclusión.
- Generar gráficos con matplotlib en `experiments/figures/`.

**Fase 7 — Materiales de entrega.** README con instrucciones de reproducción, `docs/modelo-de-amenaza.md` (activos, adversarios, capacidades, supuestos, fuera de alcance), diagramas y un borrador del informe en `docs/informe.md` con las secciones: qué hicimos, por qué es relevante, cómo lo hicimos, resultados, y aprendizajes/limitaciones.

**Fase 8 — Demo pública con Cloudflare Tunnel (sin servidor).** Todo corre en mi notebook (Windows + WSL2 + Docker) y se publica temporalmente con `cloudflared tunnel --url http://localhost:8000`, que entrega una URL `https://*.trycloudflare.com` con HTTPS.
- `make demo`: levanta el compose, inicia el túnel, muestra la URL pública y **genera un PNG con el QR de esa URL** para ponerlo en la diapositiva.
- **Código de acceso para la demo:** variable `DEMO_ACCESS_CODE` en `.env`. Se ingresa una vez y queda en una cookie `HttpOnly; Secure; SameSite=Strict`. Sin ese código, la API no lanza análisis. Esto evita que el servicio se use como proxy abierto para atacar a terceros mientras el túnel está abierto.
- Rate limit más estricto en modo demo (por ejemplo, 5 análisis por minuto por cliente) y un límite global de workers concurrentes (por ejemplo, 3).
- `make demo-stop`: cierra el túnel y apaga todo.
- **Fallback de gVisor:** si `runsc` no funciona en WSL2, el sistema detecta el problema, usa `runc` endurecido y lo deja registrado. En el informe se documenta como limitación, y el experimento compara `runc` por defecto contra `runc` endurecido (y `runsc` si se logra correr en Linux nativo).
- Grabar un video de respaldo de la demo completa (`docs/demo.mp4` o un enlace) por si falla la red el día de la presentación.
*Aceptación:* desde un celular con datos móviles (fuera de la red local) se puede abrir la URL del túnel, ingresar el código, escanear un QR y ver el análisis en vivo.

## Modelo de amenaza (punto de partida para documentar)
- **Adversario A (remoto):** controla la página de destino. Puede servir contenido hostil, intentar SSRF, agotar recursos, mostrar contenido distinto a los bots (cloaking) e intentar explotar el navegador del worker.
- **Adversario B (físico):** pega un QR falso sobre uno legítimo.
- **Adversario C (contra el log):** intenta registrar QRs a nombre de otro o reescribir el historial.
- **Fuera de alcance:** un 0-day en el kernel o en el propio gVisor (se discute como riesgo residual: KVM y el kernel siguen en el TCB), dispositivos del usuario ya comprometidos y la identidad legal de quien registra (el log prueba posesión de la clave, no la identidad, igual que los certificados DV).

## Reglas éticas (obligatorias)
- El worker solo carga páginas. Nunca envía formularios, nunca ingresa credenciales ni datos.
- Usar solo URLs de feeds públicos de investigación, con rate limiting (máximo 1 análisis cada 2 s) y sin repetir análisis innecesariamente.
- Las pruebas de contención se hacen **solo** contra infraestructura propia y local.
- No poner QRs en lugares públicos ni suplantar instituciones o personas reales.
- No guardar datos personales. Las capturas de phishing se guardan solo para el análisis.

## Cómo quiero que trabajes
- Antes de programar cada fase, muéstrame un plan corto (archivos a crear/modificar y cómo se verificará).
- Escribe los tests junto con el código y córrelos. No marques una fase como terminada si fallan.
- Mantén `CLAUDE.md` actualizado con el estado de cada fase y las decisiones tomadas.
- Si algo no alcanza a estar listo por tiempo, dímelo y propón un recorte honesto que quede documentado en las limitaciones.
- Explica las decisiones de seguridad en comentarios breves, porque las voy a defender en la presentación.

Empieza por la **Fase 0**: crea el `CLAUDE.md` y la estructura del repo, y muéstrame el plan de las fases con la fecha estimada de cada una (hoy es 6 de noviembre de 2026).
