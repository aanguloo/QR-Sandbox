// Service worker mínimo para que la web se pueda instalar como PWA.
// Estrategia "red primero": siempre se intenta la versión actual del servidor; la caché
// solo sirve para abrir la app sin conexión. NUNCA se cachean análisis ni datos del log.
const CACHE = "qrsandbox-v2";
const BASE = [
  "/", "/comercio", "/log", "/ayuda",
  "/static/css/app.css",
  "/static/js/comun.js", "/static/js/cripto.js", "/static/js/escanear.js",
  "/static/js/analisis.js", "/static/js/comercio.js", "/static/js/explorador.js",
  "/static/js/explicaciones.js",
  "/static/vendor/jsQR.js", "/static/vendor/qrcode.js",
  "/static/vendor/leaflet/leaflet.js", "/static/vendor/leaflet/leaflet.css",
  "/static/img/icono-192.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(BASE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((claves) => Promise.all(claves.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  const estatico = url.pathname.startsWith("/static/") || ["/", "/comercio", "/log", "/ayuda"].includes(url.pathname);
  if (e.request.method !== "GET" || url.origin !== location.origin || !estatico) return; // red directa
  e.respondWith(
    fetch(e.request)
      .then((r) => {
        const copia = r.clone();
        if (r.ok) caches.open(CACHE).then((c) => c.put(e.request, copia));
        return r;
      })
      .catch(() => caches.match(e.request)),
  );
});
