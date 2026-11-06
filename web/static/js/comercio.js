// Panel de comercio: la clave Ed25519 se genera y se queda EN ESTE DISPOSITIVO.
//
// - La clave privada vive en IndexedDB como CryptoKey; solo sale si el usuario descarga un
//   respaldo (acción explícita). El servidor nunca la ve: recibe registros ya firmados.
// - Lo que se firma son los bytes canónicos del registro (mismo formato que el log en
//   Python). El recibo que devuelve el log se verifica aquí antes de mostrarlo.
import { $, api, descargar, el, exigirAcceso, fecha, mostrarMensaje, registrarServiceWorker } from "./comun.js";
import {
  VERSION_REGISTRO, VERSION_REVOCACION, bytesCanonicos, exportarRespaldo, firmar, generarClaves,
  importarRespaldo, leerHoja, publicaB64, soportaEd25519, verificarHoja, verificarSth,
} from "./cripto.js";

const CLAVE_LOG_FIJADA = "qrsandbox.clave_log";
let par = null;
let publica = null;
let mapa = null;
let marcador = null;
let circulo = null;
let posicion = null;

// ------------------------------------------------------------ IndexedDB (clave local)

function abrirBD() {
  return new Promise((resolve, reject) => {
    const pedido = indexedDB.open("qrsandbox", 1);
    pedido.onupgradeneeded = () => pedido.result.createObjectStore("claves");
    pedido.onsuccess = () => resolve(pedido.result);
    pedido.onerror = () => reject(pedido.error);
  });
}

async function bd(modo, accion) {
  const db = await abrirBD();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("claves", modo);
    const pedido = accion(tx.objectStore("claves"));
    tx.oncomplete = () => resolve(pedido.result);
    tx.onerror = () => reject(tx.error);
  });
}

const guardarPar = (p) => bd("readwrite", (s) => s.put(p, "comercio"));
const cargarPar = () => bd("readonly", (s) => s.get("comercio"));

// ------------------------------------------------------------ clave

async function usarPar(nuevo) {
  par = nuevo;
  publica = await publicaB64(par);
  $("#estado-clave").replaceChildren(
    el("p", { class: "mensaje mensaje-ok" }, "Clave lista en este dispositivo."),
    el("p", { class: "pequeno" }, "Tu clave pública (es tu identidad en el log):"),
    el("code", {}, publica),
  );
  $("#boton-exportar").disabled = false;
  $("#boton-generar").textContent = "Crear otra clave";
  actualizarBotonRegistro();
  await cargarMisQrs();
}

async function generar() {
  if (par && !confirm("Ya tienes una clave. Si creas otra y no tienes respaldo, perderás el control de tus QRs registrados. ¿Continuar?")) return;
  await usarPar(await generarClaves());
  await guardarPar(par);
}

async function exportar() {
  const respaldo = await exportarRespaldo(par);
  descargar(new Blob([JSON.stringify(respaldo, null, 2)], { type: "application/json" }), "qrsandbox-clave-respaldo.json");
}

async function importar(archivo) {
  if (!archivo) return;
  try {
    const nuevo = await importarRespaldo(JSON.parse(await archivo.text()));
    await guardarPar(nuevo);
    await usarPar(nuevo);
  } catch (e) {
    mostrarMensaje($("#estado-clave"), `No se pudo importar: ${e.message}`, "error");
  }
}

// ------------------------------------------------------------ mapa

function ponerPosicion(lat, lon) {
  posicion = { lat, lon };
  const radio = Number($("#radio").value);
  if (!marcador) {
    marcador = window.L.marker([lat, lon]).addTo(mapa);
    circulo = window.L.circle([lat, lon], { radius: radio }).addTo(mapa);
  } else {
    marcador.setLatLng([lat, lon]);
    circulo.setLatLng([lat, lon]);
  }
  $("#coordenadas").textContent = `${lat.toFixed(6)}, ${lon.toFixed(6)}`;
  actualizarBotonRegistro();
}

function iniciarMapa() {
  const L = window.L;
  L.Icon.Default.imagePath = "/static/vendor/leaflet/images/";
  mapa = L.map("mapa").setView([-33.4378, -70.6505], 16); // Plaza de Armas, Santiago
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution: "© OpenStreetMap",
  }).addTo(mapa);
  mapa.on("click", (e) => ponerPosicion(e.latlng.lat, e.latlng.lng));
}

async function miUbicacion() {
  try {
    // Aquí sí se necesita precisión (es la ubicación del QR físico, no la del usuario).
    const p = await new Promise((resolve, reject) =>
      navigator.geolocation.getCurrentPosition(resolve, reject, { enableHighAccuracy: true, timeout: 10000 }));
    ponerPosicion(p.coords.latitude, p.coords.longitude);
    mapa.setView([p.coords.latitude, p.coords.longitude], 18);
  } catch {
    mostrarMensaje($("#mensaje-registro"), "No se pudo obtener tu ubicación: marca el lugar en el mapa.", "alerta");
  }
}

function actualizarBotonRegistro() {
  $("#boton-registrar").disabled = !(par && posicion);
}

// ------------------------------------------------------------ registrar

async function verificarRecibo(recibo) {
  const fijada = localStorage.getItem(CLAVE_LOG_FIJADA);
  if (fijada && fijada !== recibo.clave_log) return "la clave del log cambió desde tu última visita";
  if (!(await verificarSth(recibo.sth, recibo.clave_log))) return "la firma del log no es válida";
  if (!(await verificarHoja(recibo.indice, recibo.hoja, recibo.prueba_inclusion, recibo.sth))) {
    return "la prueba de inclusión no verifica";
  }
  localStorage.setItem(CLAVE_LOG_FIJADA, recibo.clave_log);
  return null;
}

async function registrar(e) {
  e.preventDefault();
  const salida = $("#mensaje-registro");
  try {
    const { url } = await api("/log/normalizar", { metodo: "POST", cuerpo: { url: $("#url-destino").value.trim() } });
    const registro = {
      clave_publica: publica,
      descripcion: $("#descripcion").value.trim(),
      lat_e6: Math.round(posicion.lat * 1e6),
      lon_e6: Math.round(posicion.lon * 1e6),
      radio_m: Number($("#radio").value),
      timestamp: Math.floor(Date.now() / 1000),
      url_destino: url,
      v: VERSION_REGISTRO,
    };
    const firma = await firmar(par.privateKey, bytesCanonicos(registro));
    mostrarMensaje(salida, "Registrando…");
    const recibo = await api("/log/registros", { metodo: "POST", cuerpo: { registro, firma } });
    const problema = await verificarRecibo(recibo);
    if (problema) {
      mostrarMensaje(salida, `El log respondió, pero el recibo no es confiable: ${problema}.`, "error");
      return;
    }
    mostrarMensaje(salida, `✔ Registrado como entrada #${recibo.indice}. Recibo verificado en tu navegador.`, "ok");
    mostrarQrImprimible(registro, recibo);
    await cargarMisQrs();
  } catch (err) {
    mostrarMensaje(salida, `No se pudo registrar: ${err.message}`, "error");
  }
}

// QR imprimible dibujado en un canvas (qrcode-generator solo calcula los módulos).
function dibujarQr(url, descripcion, indice) {
  const qr = window.qrcode(0, "M");
  qr.addData(url);
  qr.make();
  const modulos = qr.getModuleCount();
  const escala = 10;
  const margen = 4 * escala;
  const lado = modulos * escala + 2 * margen;
  const lienzo = el("canvas", { class: "qr-imprimible", width: lado, height: lado + 90 });
  const ctx = lienzo.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, lienzo.width, lienzo.height);
  ctx.fillStyle = "#000";
  for (let f = 0; f < modulos; f++) {
    for (let c = 0; c < modulos; c++) {
      if (qr.isDark(f, c)) ctx.fillRect(margen + c * escala, margen + f * escala, escala, escala);
    }
  }
  ctx.textAlign = "center";
  ctx.font = "bold 22px system-ui, sans-serif";
  ctx.fillText(descripcion.slice(0, 40), lado / 2, lado + 30);
  ctx.font = "16px system-ui, sans-serif";
  ctx.fillText(`Verifícalo en QR-Sandbox · registro #${indice}`, lado / 2, lado + 62);
  return lienzo;
}

function mostrarQrImprimible(registro, recibo) {
  const lienzo = dibujarQr(registro.url_destino, registro.descripcion, recibo.indice);
  const caja = $("#resultado-registro");
  caja.classList.remove("oculto");
  caja.replaceChildren(
    el("h2", {}, "Listo para imprimir"),
    lienzo,
    el("div", { class: "fila" },
      el("button", { class: "primario", type: "button", onclick: () => lienzo.toBlob((b) => descargar(b, `qr-${recibo.indice}.png`), "image/png") }, "Descargar QR (PNG)"),
      el("button", { type: "button", onclick: () => descargar(new Blob([JSON.stringify(recibo, null, 2)], { type: "application/json" }), `recibo-${recibo.indice}.json`) }, "Descargar recibo de inclusión"),
    ),
    el("p", { class: "pequeno" }, "El recibo prueba que tu registro está en el log (firma del log + prueba de inclusión). Guárdalo."),
  );
}

// ------------------------------------------------------------ mis QRs y revocación

async function cargarMisQrs() {
  const caja = $("#mis-qrs");
  if (!publica) {
    caja.replaceChildren(el("p", { class: "pequeno" }, "Crea o importa tu clave para ver tus QRs."));
    return;
  }
  try {
    const r = await api(`/log/por-clave?clave=${encodeURIComponent(publica)}`);
    const hojas = await Promise.all(r.entradas.map(async (e) => ({ indice: e.indice, ...(await leerHoja(e.hoja)) })));
    const revocados = new Set(hojas.filter((h) => h.tipo === "revocacion" && h.firmaValida).map((h) => h.contenido.indice));
    const registros = hojas.filter((h) => h.tipo === "registro");
    if (!registros.length) {
      caja.replaceChildren(el("p", { class: "pequeno" }, "Todavía no registras QRs con esta clave."));
      return;
    }
    caja.replaceChildren(el("table", { class: "tabla" },
      el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "QR"), el("th", {}, "Estado"), el("th", {}, ""))),
      el("tbody", {}, registros.map((h) => filaQr(h, revocados.has(h.indice))))));
  } catch (e) {
    mostrarMensaje(caja, `No se pudo cargar: ${e.message}`, "error");
  }
}

function filaQr(h, revocado) {
  const c = h.contenido;
  return el("tr", {},
    el("td", {}, String(h.indice)),
    el("td", {}, el("strong", {}, c.descripcion), el("br"), el("code", {}, c.url_destino),
      el("div", { class: "pequeno" }, `${fecha(h.t_log_ms)} · radio ${c.radio_m} m`)),
    el("td", {},
      el("span", { class: `etiqueta ${revocado ? "alerta" : "ok"}` }, revocado ? "revocado" : "activo"),
      h.firmaValida ? null : el("span", { class: "etiqueta mal" }, "firma inválida")),
    el("td", {}, revocado ? null : el("button", { class: "peligro", type: "button", onclick: () => revocar(h.indice) }, "Revocar")),
  );
}

async function revocar(indice) {
  const motivo = prompt("Motivo de la revocación (público):", "Ya no usamos este QR");
  if (motivo === null) return;
  try {
    const revocacion = {
      clave_publica: publica,
      indice,
      motivo: motivo.slice(0, 200),
      timestamp: Math.floor(Date.now() / 1000),
      v: VERSION_REVOCACION,
    };
    const firma = await firmar(par.privateKey, bytesCanonicos(revocacion));
    const recibo = await api("/log/revocaciones", { metodo: "POST", cuerpo: { revocacion, firma } });
    const problema = await verificarRecibo(recibo);
    mostrarMensaje($("#mensaje-registro"), problema ? `Revocado, pero el recibo no verifica: ${problema}` : `✔ QR #${indice} revocado (entrada #${recibo.indice}).`, problema ? "error" : "ok");
    await cargarMisQrs();
  } catch (e) {
    mostrarMensaje($("#mensaje-registro"), `No se pudo revocar: ${e.message}`, "error");
  }
}

// ------------------------------------------------------------ inicio

async function iniciar() {
  iniciarMapa();
  exigirAcceso($("main"));
  $("#radio").addEventListener("input", (e) => {
    $("#radio-valor").textContent = e.target.value;
    if (circulo) circulo.setRadius(Number(e.target.value));
  });
  $("#boton-mi-ubicacion").addEventListener("click", miUbicacion);
  $("#form-registro").addEventListener("submit", registrar);
  $("#boton-generar").addEventListener("click", generar);
  $("#boton-exportar").addEventListener("click", exportar);
  $("#archivo-respaldo").addEventListener("change", (e) => importar(e.target.files[0]));

  if (!globalThis.isSecureContext || !(await soportaEd25519())) {
    mostrarMensaje($("#estado-clave"), "Este navegador no permite firmar con Ed25519 aquí (se necesita HTTPS y un navegador actual).", "error");
    $("#boton-generar").disabled = true;
    return;
  }
  const guardado = await cargarPar().catch(() => null);
  if (guardado) await usarPar(guardado);
  else {
    mostrarMensaje($("#estado-clave"), "Todavía no tienes una clave en este dispositivo.");
    await cargarMisQrs();
  }
}

// Leaflet y qrcode se cargan con "defer": esperamos a que el documento esté listo.
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", iniciar);
else iniciar();
registrarServiceWorker();
