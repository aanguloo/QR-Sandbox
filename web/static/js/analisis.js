// Resultado del análisis, en vivo por Server-Sent Events.
//
// Todo lo que viene del sitio analizado (URLs, títulos, nombres de archivo) es ENTRADA DEL
// ATACANTE: se muestra con el(...)/textContent, nunca como HTML. La vista previa son solo
// imágenes JPEG mostradas desde un blob: con tipo fijo image/jpeg.
import { $, b64aBytes, el, fecha, hrefSeguro, registrarServiceWorker } from "./comun.js";
import { leerHoja, verificarHoja, verificarSth } from "./cripto.js";
import { EXPLICACIONES, ICONOS_PERMISO, QUE_HACER } from "./explicaciones.js";

const id = location.pathname.split("/").pop();
const linea = $("#linea");
const pantalla = $("#pantalla");
const MAX_TERCEROS_VISIBLES = 6;
let urlFrame = null;
let terceros = 0;
let filaTerceros = null;
let ultimoSeq = -1; // al reconectar o cambiar de canal se ignora lo ya visto
const fotosVistas = new Set();

const ESTADOS = {
  peligroso: { titulo: "Peligroso", texto: "No lo abras." },
  sospechoso: { titulo: "Sospechoso", texto: "Revisa bien antes de abrirlo." },
  sin_alertas: { titulo: "Sin alertas", texto: "No encontramos señales de riesgo." },
};

function host(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return String(url);
  }
}

function agregar(icono, texto, detalle) {
  const li = el("li", {}, `${icono} ${texto}`, detalle ? el("span", { class: "detalle" }, detalle) : null);
  linea.append(li);
  return li;
}

// ------------------------------------------------------------ eventos en vivo

function alEvento(ev) {
  switch (ev.tipo) {
    case "redireccion":
      agregar("🔀", `Redirige de ${host(ev.desde)} a ${host(ev.hacia)}`, ev.hacia);
      break;
    case "navegacion":
      agregar("🌐", `Llegó a ${host(ev.url)}`, ev.url);
      break;
    case "request_tercero":
      terceros += 1;
      if (terceros <= MAX_TERCEROS_VISIBLES) {
        agregar("📡", `Contacta ${ev.dominio}`);
      } else {
        // Agrupación: "+N dominios más" en vez de una línea por cada uno (anti-DoS visual).
        filaTerceros ??= agregar("📡", "");
        filaTerceros.firstChild.textContent = `📡 +${terceros - MAX_TERCEROS_VISIBLES} dominios de terceros más`;
      }
      break;
    case "formulario_password":
      agregar("⚠️", "Muestra un formulario que pide contraseña");
      break;
    case "descarga_bloqueada":
      agregar("⛔", `Intentó descargar «${ev.nombre}» (bloqueado)`, ev.url);
      break;
    case "marca_detectada":
      agregar("🖼️", `Muestra la marca ${ev.marca} en ${ev.dominio}`);
      break;
    case "permiso_solicitado": {
      const [icono, que] = ICONOS_PERMISO[ev.permiso] || ["⚠️", ev.permiso];
      agregar(icono, `La página pidió acceso a ${que} (el sandbox se lo negó)`);
      break;
    }
    case "error":
      agregar("⚠️", ev.mensaje);
      break;
    default:
      break;
  }
}

function alEstatico(d) {
  const datos = d.datos || {};
  if (Number.isInteger(datos.edad_dominio_dias)) {
    const dias = datos.edad_dominio_dias;
    const cuando = dias === 0 ? "hoy" : dias === 1 ? "ayer" : dias < 365 ? `hace ${dias} días` : `hace ${Math.floor(dias / 365)} años`;
    agregar("📅", `El dominio ${datos.dominio} se registró ${cuando}`);
  }
  if (datos.certificado) {
    const c = datos.certificado;
    agregar(c.valido ? "🔒" : "⚠️", c.valido ? `Certificado emitido el ${fecha(Date.parse(c.emitido))} por ${c.emisor}` : "El certificado no es válido");
  }
  if (Number.isInteger(datos.rango_tranco)) agregar("⭐", `Sitio popular (#${datos.rango_tranco} en Tranco)`);
  for (const h of d.hallazgos || []) if (h.peso >= 30) agregar("⚠️", h.razon);
}

function alFrame(d) {
  const blob = new Blob([b64aBytes(d.jpeg_b64)], { type: "image/jpeg" });
  const nueva = URL.createObjectURL(blob);
  pantalla.src = nueva;
  if (urlFrame) URL.revokeObjectURL(urlFrame);
  urlFrame = nueva;
}

// ------------------------------------------------------------ fotos paso a paso

function ampliarFoto(foto) {
  const caja = $("#foto-ampliada");
  const yaAbierta = caja.dataset.n === String(foto.n) && !caja.classList.contains("oculto");
  caja.classList.toggle("oculto", yaAbierta);
  caja.dataset.n = String(foto.n);
  caja.replaceChildren(
    el("img", { src: foto.url, alt: foto.etiqueta }),
    el("figcaption", {}, `${foto.etiqueta} · ${(foto.t_ms / 1000).toFixed(1)} s`),
  );
}

function agregarFoto(foto) {
  if (fotosVistas.has(foto.n) || !/^\/analisis\/[0-9a-f]{32}\/fotos\/\d+$/.test(foto.url)) return;
  fotosVistas.add(foto.n);
  $("#seccion-fotos").classList.remove("oculto");
  $("#fotos").append(el("button", { class: "foto", type: "button", title: foto.etiqueta, onclick: () => ampliarFoto(foto) },
    el("img", { src: foto.url, alt: "", loading: "lazy" }),
    el("span", {}, foto.etiqueta)));
}

function rehacerGaleria(fotos) {
  // Al terminar, las etiquetas definitivas (p. ej. "· captura final") vienen en el resultado.
  fotosVistas.clear();
  $("#fotos").replaceChildren();
  (fotos || []).forEach(agregarFoto);
}

// ------------------------------------------------------------ resultado final

function mostrarVeredicto(v) {
  const caja = $("#veredicto");
  const e = ESTADOS[v.estado] || ESTADOS.sospechoso;
  caja.className = `tarjeta veredicto veredicto-${v.estado}`;
  caja.replaceChildren(
    el("p", { class: "estado" }, `${e.titulo} `, el("span", { class: "puntaje" }, `${v.puntaje}/100`)),
    el("p", {}, v.resumen),
    v.razones.length
      ? el("ol", { class: "razones" }, v.razones.map((r) =>
        el("li", {}, r.razon, el("span", { class: "peso" }, r.peso > 0 ? `+${r.peso}` : `${r.peso}`),
          EXPLICACIONES[r.codigo]
            ? el("details", { class: "explicacion" }, el("summary", {}, "¿Qué significa?"), el("p", {}, EXPLICACIONES[r.codigo]))
            : null)))
      : null,
    el("div", { class: "que-hacer" }, el("strong", {}, "Qué hacer ahora"),
      el("ul", {}, (QUE_HACER[v.estado] || []).map((t) => el("li", {}, t)))),
    el("p", { class: "pequeno" }, e.texto, " El puntaje (0 a 100) es la suma de los puntos de cada razón: 70 o más es peligroso, 35 a 69 sospechoso."),
  );
}

async function mostrarLog(log) {
  const caja = $("#log");
  caja.classList.remove("oculto");
  if (!log) {
    caja.replaceChildren(
      el("p", { class: "log-estado" }, "❔ Registro de QRs no consultado"),
      el("p", { class: "pequeno" }, "No compartiste tu ubicación, así que no comprobamos si el comercio registró este QR."),
    );
    return;
  }
  const hijos = [];
  if (log.estado === "verificado") {
    hijos.push(el("p", { class: "log-estado" }, "✅ Verificado: el comercio registró este QR aquí"));
    const c = log.coincidencias[0];
    const hoja = await leerHoja(c.hoja);
    hijos.push(el("p", {}, `«${hoja.contenido.descripcion}», registrado el ${fecha(hoja.t_log_ms)} (a ~${c.distancia_m} m).`));
    // Verificación en el navegador: firma del log sobre la raíz + prueba de inclusión + firma del comercio.
    const ok = (await verificarSth(log.sth, log.clave_log))
      && (await verificarHoja(c.indice, c.hoja, c.prueba_inclusion, log.sth)) && hoja.firmaValida;
    hijos.push(el("p", { class: `mensaje ${ok ? "mensaje-ok" : "mensaje-error"}` },
      ok ? "✔ Comprobado en tu navegador: firma del comercio, prueba de inclusión y firma del log."
        : "✘ La prueba NO verifica en tu navegador: no confíes en este registro."));
  } else if (log.estado === "no_coincide") {
    hijos.push(el("p", { class: "log-estado" }, "⚠️ No coincide: posible sticker encima del QR original"));
    hijos.push(el("p", {}, "En este lugar hay QRs registrados que apuntan a otro sitio:"));
    const lista = el("ul");
    for (const o of log.otros_destinos_cercanos.slice(0, 3)) {
      const h = await leerHoja(o.hoja);
      lista.append(el("li", {}, el("code", {}, h.contenido.url_destino), ` — «${h.contenido.descripcion}» (a ~${o.distancia_m} m)`));
    }
    hijos.push(lista);
  } else {
    hijos.push(el("p", { class: "log-estado" }, "❔ Sin registro"));
    hijos.push(el("p", { class: "pequeno" }, "Ningún comercio registró un QR aquí. El veredicto se basa solo en el análisis del enlace."));
  }
  hijos.push(el("details", { class: "explicacion" }, el("summary", {}, "¿Qué es el registro de QRs?"),
    el("p", {}, "Los comercios pueden registrar sus QRs con una firma digital y la ubicación donde los pegaron. "
      + "Si escaneas un QR en ese lugar y lleva a otro sitio, probablemente alguien pegó un sticker falso encima. "
      + "Tu teléfono verifica la firma por su cuenta: no tienes que confiar en nuestro servidor.")));
  if (log.revocados_cercanos?.length) {
    hijos.push(el("p", { class: "pequeno" }, `Hay ${log.revocados_cercanos.length} QR(s) revocados por su comercio en esta zona.`));
  }
  caja.replaceChildren(...hijos);
}

function mostrarDetalles(r) {
  const caja = $("#detalles");
  caja.classList.remove("oculto");
  const res = r.resultado;
  // La captura final ya se ve arriba (último frame de la vista previa): no se repite aquí.
  const hijos = [el("h2", {}, "Detalles")];
  if (res?.cadena_redirecciones?.length) {
    hijos.push(el("p", {}, `Cadena de redirecciones (${res.cadena_redirecciones.length - 1} saltos):`));
    hijos.push(el("ol", { class: "cadena" }, res.cadena_redirecciones.map((u) => el("li", {}, u))));
  }
  if (res) {
    hijos.push(el("p", {}, "Título de la página: ", el("code", {}, res.titulo || "(sin título)")));
  }
  const tecnico = el("details", {}, el("summary", {}, "Datos técnicos del sandbox"),
    el("ul", {},
      el("li", {}, `Aislamiento: ${r.perfil} (${r.runtime})${r.aviso_runtime ? ` — ${r.aviso_runtime}` : ""}`),
      el("li", {}, `Duración: ${(r.duracion_ms / 1000).toFixed(1)} s · frames: ${r.frames}`),
      el("li", {}, `Eventos descartados por inválidos: ${r.eventos_descartados} · por tasa: ${r.descartados_tasa}`),
      res ? el("li", {}, `Dominios de terceros: ${res.n_dominios_terceros} · formularios con contraseña: ${res.formularios_password}`) : null,
      el("li", {}, `Contenedor eliminado: ${r.contenedor_eliminado ? "sí" : "NO"}`),
    ));
  hijos.push(tecnico);
  caja.replaceChildren(...hijos);
}

// "Abrir de todas formas": nunca automático, con advertencia y confirmación explícita.
function mostrarAbrir(r) {
  const caja = $("#abrir");
  caja.classList.remove("oculto");
  const destino = r.resultado?.url_final || r.url;
  const peligroso = r.veredicto.estado !== "sin_alertas";
  const enlace = el("a", { class: "boton oculto", href: hrefSeguro(destino), target: "_blank", rel: "noopener noreferrer" },
    `Abrir ${host(destino)}`);
  const casilla = el("input", { type: "checkbox", id: "entiendo" });
  casilla.addEventListener("change", () => enlace.classList.toggle("oculto", !casilla.checked));
  caja.replaceChildren(
    el("h2", {}, "Abrir de todas formas"),
    el("div", { class: peligroso ? "aviso-abrir pila" : "pila" },
      el("p", {}, peligroso
        ? `Vas a abrir ${host(destino)} en tu teléfono, fuera del sandbox. No ingreses contraseñas, datos de tarjetas ni tu RUT.`
        : `Se abrirá ${host(destino)} fuera del sandbox. Aun sin alertas, revisa que sea el sitio que esperas antes de ingresar datos.`),
      el("label", { class: "casilla", for: "entiendo" }, casilla, el("span", {}, "Entiendo el riesgo y quiero abrirlo")),
      enlace),
  );
}

async function alFin(r) {
  rehacerGaleria(r.fotos);
  $("#punto-vivo").classList.add("oculto");
  $("#titulo-vivo").lastChild.textContent = "Lo que hizo el link";
  $("#veredicto").classList.remove("oculto");
  mostrarVeredicto(r.veredicto);
  if (r.captura_url) {
    pantalla.src = r.captura_url; // captura final servida como image/jpeg desde su propia ruta
    if (urlFrame) URL.revokeObjectURL(urlFrame);
    urlFrame = null;
  }
  mostrarDetalles(r);
  mostrarAbrir(r);
  await mostrarLog(r.log);
}

// Canal en vivo: SSE primero (spec). Si en ESPERA_SSE_MS no llega nada, se cambia a sondeo:
// algunos intermediarios retienen el SSE (medido: el borde de Cloudflare de los túneles
// gratuitos guarda ~500 KB antes de dejarlo pasar). El sondeo pide el progreso y la imagen
// actual cada SONDEO_MS; cada respuesta llega completa, así que nada la retiene.
const ESPERA_SSE_MS = 2500;
const SONDEO_MS = 700;
let terminado = false;
let recibioAlgo = false;

function despachar(tipo, datos, seq) {
  if (seq !== undefined && seq !== null) {
    if (seq <= ultimoSeq) return; // ya mostrado (reconexión o cambio de canal)
    ultimoSeq = seq;
  }
  recibioAlgo = true;
  if (tipo === "evento") alEvento(datos);
  else if (tipo === "foto") agregarFoto(datos);
  else if (tipo === "estatico") alEstatico(datos);
  else if (tipo === "frame") alFrame(datos);
  else if (tipo === "fin") {
    terminado = true;
    $("#url-analizada").textContent = datos.url;
    alFin(datos);
  } else if (tipo === "fallo") {
    terminado = true;
    $("#punto-vivo").classList.add("oculto");
    agregar("⚠️", `El análisis no terminó: ${datos.mensaje}`);
  }
}

function escucharSse() {
  const fuente = new EventSource(`/analisis/${id}/eventos`);
  for (const tipo of ["evento", "foto", "estatico", "frame", "fin", "fallo"]) {
    fuente.addEventListener(tipo, (e) => {
      despachar(tipo, JSON.parse(e.data), e.lastEventId === "" ? null : Number(e.lastEventId));
      if (terminado) fuente.close();
    });
  }
  fuente.onerror = () => {
    if (fuente.readyState === EventSource.CLOSED && !terminado) agregar("⚠️", "Se perdió la conexión con el servidor.");
  };
  setTimeout(() => {
    if (!recibioAlgo && !terminado) {
      fuente.close();
      sondear();
    }
  }, ESPERA_SSE_MS);
}

async function sondear() {
  let frameVisto = 0;
  while (!terminado) {
    try {
      const r = await fetch(`/analisis/${id}/progreso?desde=${ultimoSeq + 1}`).then((x) => x.json());
      for (const e of r.eventos) despachar(e.tipo, e.datos, e.seq);
      if (!terminado && r.frame_seq !== frameVisto) {
        frameVisto = r.frame_seq;
        if (urlFrame) URL.revokeObjectURL(urlFrame);
        urlFrame = null;
        pantalla.src = `/analisis/${id}/frame?n=${frameVisto}`; // image/jpeg directo del servidor
      }
      if (r.estado !== "en_curso" && !r.eventos.length) break;
    } catch {
      // red inestable (p. ej. datos móviles): se reintenta en el próximo ciclo
    }
    await new Promise((listo) => setTimeout(listo, SONDEO_MS));
  }
}

function iniciar() {
  if (!/^[0-9a-f]{32}$/.test(id)) {
    agregar("⚠️", "Identificador de análisis inválido.");
    return;
  }
  escucharSse();
  fetch(`/analisis/${id}/resultado`).then((r) => (r.ok ? r.json() : null)).then((d) => {
    if (d) $("#url-analizada").textContent = d.url;
    else agregar("⚠️", "Este análisis no existe o ya expiró.");
  }).catch(() => {});
}

iniciar();
registrarServiceWorker();
