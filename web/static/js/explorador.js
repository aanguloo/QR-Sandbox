// Explorador del QR Transparency Log: todo se verifica en el navegador.
//
// - La clave del log se fija la primera vez (TOFU) y se avisa si cambia.
// - Se guarda el último STH visto: en cada visita se pide una prueba de consistencia y se
//   comprueba que el log solo CRECIÓ (no reescribió el historial), como un auditor de CT.
import { $, api, el, fecha, hexABytes, mostrarMensaje, registrarServiceWorker } from "./comun.js";
import { leerHoja, verificarConsistencia, verificarHoja, verificarSth } from "./cripto.js";

const CLAVE_LOG_FIJADA = "qrsandbox.clave_log";
const ULTIMO_STH = "qrsandbox.ultimo_sth";
const PAGINA = 25;
let claveLog = null;
let sth = null;
let siguiente = 0;

async function consistentes(viejo, nuevo) {
  if (viejo.tamano === 0) return true;
  if (viejo.tamano === nuevo.tamano) return viejo.raiz === nuevo.raiz;
  const p = await api(`/log/prueba-consistencia?primero=${viejo.tamano}&segundo=${nuevo.tamano}`);
  return verificarConsistencia(viejo.tamano, nuevo.tamano, hexABytes(viejo.raiz), hexABytes(nuevo.raiz), p.ruta.map(hexABytes));
}

async function cargarSth() {
  const caja = $("#seccion-sth");
  const { clave_publica: clave } = await api("/log/clave-publica");
  const fijada = localStorage.getItem(CLAVE_LOG_FIJADA);
  claveLog = fijada || clave;
  sth = await api("/log/sth");
  const firmaOk = await verificarSth(sth, claveLog);

  const hijos = [
    el("h2", {}, "Raíz firmada actual (STH)"),
    el("p", {}, `${sth.tamano} entradas · firmada el ${fecha(sth.timestamp_ms)}`),
    el("p", {}, "Raíz: ", el("code", {}, sth.raiz)),
    el("p", { class: "pequeno" }, "Clave del log: ", el("code", {}, clave)),
    el("p", { class: `mensaje ${firmaOk ? "mensaje-ok" : "mensaje-error"}` },
      firmaOk ? "✔ Firma del log verificada en tu navegador." : "✘ La firma del STH no verifica con la clave fijada."),
  ];
  if (fijada && fijada !== clave) {
    hijos.push(el("p", { class: "mensaje mensaje-error" }, "✘ ¡La clave del log cambió desde tu última visita!"));
  }
  const anterior = JSON.parse(localStorage.getItem(ULTIMO_STH) || "null");
  if (anterior && firmaOk) {
    const ok = await consistentes(anterior, sth);
    hijos.push(el("p", { class: `mensaje ${ok ? "mensaje-ok" : "mensaje-error"}` }, ok
      ? `✔ Desde tu última visita el log solo creció (${anterior.tamano} → ${sth.tamano} entradas).`
      : `✘ ALERTA: el log no es una extensión del que viste antes (${anterior.tamano} → ${sth.tamano}).`));
    if (ok) localStorage.setItem(ULTIMO_STH, JSON.stringify(sth));
  } else if (firmaOk) {
    localStorage.setItem(ULTIMO_STH, JSON.stringify(sth));
    hijos.push(el("p", { class: "pequeno" }, "Primera visita: se guarda esta raíz para comprobar en las próximas que el log solo crezca."));
  }
  if (!fijada && firmaOk) localStorage.setItem(CLAVE_LOG_FIJADA, clave);
  caja.replaceChildren(...hijos);
}

function describir(h) {
  const c = h.contenido;
  if (h.tipo === "revocacion") return [el("strong", {}, `Revoca el #${c.indice}`), el("div", { class: "pequeno" }, c.motivo)];
  return [el("strong", {}, c.descripcion), el("br"), el("code", {}, c.url_destino),
    el("div", { class: "pequeno" }, `${(c.lat_e6 / 1e6).toFixed(5)}, ${(c.lon_e6 / 1e6).toFixed(5)} · radio ${c.radio_m} m`)];
}

function fila(indice, hojaTexto, h) {
  const estado = el("td", {}, el("button", { type: "button", onclick: () => verificarFila(indice, hojaTexto, h, estado) }, "Verificar"));
  return el("tr", {},
    el("td", {}, String(indice)),
    el("td", {}, ...describir(h), el("div", { class: "pequeno" }, `${fecha(h.t_log_ms)} · clave ${h.contenido.clave_publica.slice(0, 12)}…`)),
    estado);
}

async function verificarFila(indice, hojaTexto, h, celda) {
  const p = await api(`/log/prueba-inclusion?indice=${indice}&tamano=${sth.tamano}`);
  const incluida = await verificarHoja(indice, hojaTexto, p.ruta, sth);
  celda.replaceChildren(
    el("span", { class: `etiqueta ${incluida ? "ok" : "mal"}` }, incluida ? "✔ en el árbol" : "✘ no está"),
    el("br"),
    el("span", { class: `etiqueta ${h.firmaValida ? "ok" : "mal"}` }, h.firmaValida ? "✔ firma" : "✘ firma"),
  );
}

async function cargarMas() {
  const r = await api(`/log/registros?desde=${siguiente}&limite=${PAGINA}`);
  let tabla = $("#lista table tbody");
  if (!tabla) {
    tabla = el("tbody");
    $("#lista").replaceChildren(el("table", { class: "tabla" },
      el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "Entrada"), el("th", {}, "Verificación"))), tabla));
  }
  for (const e of r.entradas) {
    if (e.indice >= sth.tamano) continue; // solo lo cubierto por la raíz firmada
    tabla.append(fila(e.indice, e.hoja, await leerHoja(e.hoja)));
  }
  siguiente += r.entradas.length;
  $("#boton-mas").classList.toggle("oculto", siguiente >= sth.tamano);
  if (sth.tamano === 0) $("#lista").replaceChildren(el("p", { class: "pequeno" }, "El log está vacío."));
}

async function consistenciaManual(e) {
  e.preventDefault();
  const caja = $("#resultado-consistencia");
  const a = Number($("#tam-a").value);
  const b = Number($("#tam-b").value);
  try {
    const [sa, sb] = await Promise.all([api(`/log/sth/${a}`), api(`/log/sth/${b}`)]);
    const firmas = (await verificarSth(sa, claveLog)) && (await verificarSth(sb, claveLog));
    const ok = firmas && (await consistentes(sa, sb));
    mostrarMensaje(caja, ok ? `✔ La raíz de ${b} entradas extiende a la de ${a}: el historial no se reescribió.`
      : `✘ Las raíces de ${a} y ${b} NO son consistentes${firmas ? "" : " (firma inválida)"}.`, ok ? "ok" : "error");
  } catch (err) {
    mostrarMensaje(caja, err.message, "error");
  }
}

async function auditarClave(e) {
  e.preventDefault();
  const caja = $("#resultado-auditoria");
  const clave = $("#clave-auditoria").value.trim();
  mostrarMensaje(caja, "Descargando el log…");
  try {
    const propias = [];
    for (let desde = 0; desde < sth.tamano; desde += 500) {
      const r = await api(`/log/registros?desde=${desde}&limite=500`);
      for (const ent of r.entradas) {
        if (ent.indice >= sth.tamano) continue;
        const h = await leerHoja(ent.hoja);
        if (h.contenido.clave_publica === clave) propias.push(fila(ent.indice, ent.hoja, h));
      }
    }
    caja.replaceChildren(propias.length
      ? el("table", { class: "tabla" }, el("tbody", {}, propias))
      : el("p", { class: "mensaje" }, "No hay entradas con esa clave."));
  } catch (err) {
    mostrarMensaje(caja, err.message, "error");
  }
}

async function iniciar() {
  try {
    await cargarSth();
    await cargarMas();
  } catch (e) {
    mostrarMensaje($("#seccion-sth"), `No se pudo cargar el log: ${e.message}`, "error");
  }
  $("#boton-mas").addEventListener("click", cargarMas);
  $("#form-consistencia").addEventListener("submit", consistenciaManual);
  $("#form-auditoria").addEventListener("submit", auditarClave);
}

iniciar();
registrarServiceWorker();
