# Guion de la demo y del video de respaldo

Para la presentación del 19-nov. La demo en vivo dura unos 5 minutos de los 15.

## El día anterior (obligatorio)

1. **Probar la demo completa desde un celular con datos móviles**, no Wi-Fi, que es la
   prueba de aceptación de la Fase 8:
   ```bash
   cd ~/QR-Sandbox && make demo
   ```
   Escanea el QR de `data/demo/qr-demo.png`, ingresa el código, analiza un enlace y mira que
   la línea de tiempo y las fotos aparezcan en vivo.
2. **Limpiar el log de pruebas.** Así la demo parte limpia; también se borra la clave del log:
   ```bash
   make demo-stop && docker compose down -v
   ```
3. **Grabar el video de respaldo** (ver más abajo) por si falla la red en la sala.
4. Elegir el **enlace de phishing para mostrar**: al final de este documento hay un comando
   para tomar uno del feed de hoy.

## Antes de presentar (10 minutos antes)

```bash
cd ~/QR-Sandbox && make demo
```
- La URL de `trycloudflare.com` **cambia cada vez**: el PNG `data/demo/qr-demo.png` se
  regenera. Ponlo en la diapositiva en ese momento, o muéstralo en pantalla completa desde
  el Explorador de Windows (`\\wsl.localhost\Ubuntu\home\andre\QR-Sandbox\data\demo\`).
- El **código de acceso** aparece en la terminal y está guardado en `.env`. Dilo en voz alta o
  escríbelo en la pizarra. **No lo pongas en la diapositiva**: la diapositiva podría
  circular después.
- **Registra el QR del "comercio" en la sala**, desde tu celular y estando en la sala:
  Comercio → Crear clave → "Usar mi ubicación" → enlace `https://example.com`, descripción
  "Carta de la cafetería" → Firmar y registrar.

## Durante la demo (unos 5 minutos)

1. **El problema (30 s).** "Un QR no te dice a dónde lleva. Basta un sticker encima."
2. **El público escanea (1 min).** Muestra el QR de la diapositiva. Cada uno ingresa el código.
3. **Análisis en vivo (1,5 min).** Pega el enlace de phishing del día en Escanear →
   Analizar. Muestra la línea de tiempo, la vista previa en vivo ("a tu teléfono solo llegan
   imágenes"), las fotos paso a paso y el veredicto con sus razones y "¿Qué significa?".
4. **El sticker (1,5 min), la innovación principal.** Estando en la sala y con ubicación:
   - analiza `https://example.com` → **✅ Verificado**, comprobado en el navegador;
   - analiza `https://example.org` (el "sticker") → **⚠️ No coincide: posible sticker**.
5. **El log (30 s).** Abre Log: "✔ Firma del log verificada en tu navegador". Toca
   "Verificar" en el registro de la sala.

Al terminar la presentación:
```bash
make demo-stop
```

## Si algo falla

| Problema | Qué hacer |
|---|---|
| La red de la sala bloquea o el túnel no levanta | Poner el **video de respaldo** |
| El sitio de phishing ya murió | Usar otro del feed (comando abajo) o mostrar el caso guardado en el video |
| La URL no abre en los celulares | Esperar unos 30 s: el DNS de trycloudflare tarda en propagarse |
| "Demasiados análisis" (429) | Es el límite de la demo (5/min por persona, 20/min en total): esperar un minuto |
| gVisor no está disponible | El sistema usa runc endurecido solo y lo informa en los detalles técnicos; seguir |

## Grabar el video de respaldo

Guárdalo como `docs/demo.mp4`. GitHub rechaza archivos de más de 100 MB; si pesa más, súbelo a
Drive o YouTube (no listado) y deja el enlace en `docs/demo-video.txt`.

1. **Pantalla del PC:** en Windows, con el navegador abierto, usa **Win + Alt + R** (Barra
   de juego de Xbox) para empezar y detener la grabación. Queda en `Videos\Capturas`.
2. **Celular:** usa la grabación de pantalla del propio teléfono (Android: panel rápido →
   "Grabar pantalla"; iPhone: Centro de control → grabar).
3. Sigue los pasos 2 a 5 de "Durante la demo", hablando por encima, en unos 3–4 minutos.
4. Si quieres, une ambos videos (PC y celular) con el editor de Fotos de Windows (Clipchamp).

## Elegir el enlace de phishing del día

Toma un enlace del feed público de hoy que todavía esté vivo. Solo se analiza en el sandbox
y **nunca se abre fuera de él**:
```bash
cd ~/QR-Sandbox && make listas
grep -h '^https://' data/listas/snapshots/urls-openphish-$(date -u +%F).txt | head -20
```
Prueba 2 o 3 en la app (Escanear → pegar enlace) y quédate con uno que cargue y salga
**Peligroso** con razones fáciles de explicar, por ejemplo imitación de marca o dominio nuevo.
