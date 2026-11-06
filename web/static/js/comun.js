// Utilidades compartidas de la web de QR-Sandbox.
//
// REGLA DE SEGURIDAD: todo texto que no escribimos nosotros (títulos y URLs de páginas
// analizadas, descripciones del log...) se inserta como TEXTO con el(...) / textContent.
// Nunca innerHTML, outerHTML, insertAdjacentHTML, document.write ni eval: un <title> con
// <script> de un sitio malicioso debe verse como texto, no ejecutarse. Hay un test que
// revisa que esas funciones no aparezcan en este directorio.
// Este módulo no toca el DOM al importarse (así también se puede probar con Node).

// Cabecera anti-CSRF exigida por la API en POST (ver api/seguridad.py).
export const CABECERA_CSRF = { "X-QRSandbox-CSRF": "1" };

export async function api(ruta, { metodo = "GET", cuerpo } = {}) {
  const opciones = { method: metodo, headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (cuerpo !== undefined) {
    Object.assign(opciones.headers, { "Content-Type": "application/json" }, CABECERA_CSRF);
    opciones.body = JSON.stringify(cuerpo);
  }
  const r = await fetch(ruta, opciones);
  let datos = null;
  try {
    datos = await r.json();
  } catch {
    datos = null;
  }
  if (!r.ok) {
    const detalle = datos && typeof datos.detail === "string" ? datos.detail : `error ${r.status}`;
    throw new Error(detalle);
  }
  return datos;
}

// Solo esquemas inofensivos en enlaces (nada de javascript:, data:, etc.).
export function hrefSeguro(valor) {
  try {
    const u = new URL(valor, globalThis.location?.href);
    return ["http:", "https:", "blob:"].includes(u.protocol) ? u.href : "#";
  } catch {
    return "#";
  }
}

// Construye un elemento. Los hijos que no son nodos se agregan como TEXTO.
// Atributos "on*" solo aceptan funciones (nunca código en texto).
export function el(etiqueta, atributos = {}, ...hijos) {
  const nodo = document.createElement(etiqueta);
  for (const [clave, valor] of Object.entries(atributos)) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (clave.startsWith("on")) {
      if (typeof valor === "function") nodo.addEventListener(clave.slice(2), valor);
      continue;
    }
    if (clave === "class") nodo.className = valor;
    else if (clave === "href") nodo.setAttribute("href", hrefSeguro(valor));
    else nodo.setAttribute(clave, valor === true ? "" : String(valor));
  }
  for (const hijo of hijos.flat()) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    nodo.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
  }
  return nodo;
}

export function $(selector) {
  return document.querySelector(selector);
}

export function mostrarMensaje(contenedor, texto, tipo = "info") {
  contenedor.replaceChildren(el("p", { class: `mensaje mensaje-${tipo}`, role: "status" }, texto));
}

export function b64aBytes(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

export function bytesAB64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

export function hexABytes(hex) {
  if (typeof hex !== "string" || !/^([0-9a-f]{2})*$/.test(hex)) throw new Error("hex inválido");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export function bytesAHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Descarga un Blob como archivo (sin abrir ventanas).
export function descargar(blob, nombre) {
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: nombre });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function fecha(ms) {
  return new Date(ms).toLocaleString("es-CL");
}

export function registrarServiceWorker() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
}

// Ubicación aproximada: se redondea a 3 decimales (~110 m) ANTES de salir del teléfono.
export function ubicacionAproximada(timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) return reject(new Error("este navegador no da ubicación"));
    navigator.geolocation.getCurrentPosition(
      (p) => resolve({
        lat: Math.round(p.coords.latitude * 1000) / 1000,
        lon: Math.round(p.coords.longitude * 1000) / 1000,
        precision: p.coords.accuracy,
      }),
      (e) => reject(new Error(e.code === 1 ? "permiso de ubicación denegado" : "no se pudo obtener la ubicación")),
      { enableHighAccuracy: true, timeout: timeoutMs, maximumAge: 60000 },
    );
  });
}

// Demo pública (Fase 8): si el servidor pide código de acceso y aún no lo tenemos, muestra un
// formulario al comienzo de `contenedor`. El código se manda una vez; el servidor responde con
// una cookie HttpOnly (este JS nunca la ve). Devuelve una promesa que se cumple con acceso.
export async function exigirAcceso(contenedor) {
  let estado;
  try {
    estado = await api("/acceso/estado");
  } catch {
    return;
  }
  if (!estado.requerido || estado.ok) return;
  await new Promise((resolver) => {
    const entrada = el("input", { type: "password", autocomplete: "off", required: true, "aria-label": "Código de acceso" });
    const mensaje = el("div", { "aria-live": "polite" });
    const formulario = el("form", { class: "tarjeta pila acceso" },
      el("h2", {}, "Código de acceso"),
      el("p", {}, "Esta es una demo pública: para analizar enlaces o registrar QRs, ingresa el código que se mostró en la presentación."),
      el("div", { class: "fila" }, entrada, el("button", { class: "primario", type: "submit" }, "Entrar")),
      mensaje);
    formulario.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api("/acceso", { metodo: "POST", cuerpo: { codigo: entrada.value } });
        formulario.remove();
        resolver();
      } catch (err) {
        mostrarMensaje(mensaje, err.message, "error");
      }
    });
    contenedor.prepend(formulario);
    entrada.focus();
  });
}

export const esErrorDeAcceso = (e) => /código de acceso/.test(e?.message || "");
