// Escanear: decodifica el QR EN EL NAVEGADOR y muestra el destino antes de hacer nada.
// Nunca se navega al destino desde aquí: solo se manda el texto al sandbox.
import { $, api, esErrorDeAcceso, exigirAcceso, mostrarMensaje, registrarServiceWorker, ubicacionAproximada } from "./comun.js";

const video = $("#video");
const lienzo = $("#lienzo");
const ctx = lienzo.getContext("2d", { willReadFrequently: true });
const MAX_LADO = 1600; // las fotos se reducen antes de decodificar (memoria y velocidad)
let flujo = null;
let destino = null;

function decodificar(ancho, alto) {
  const imagen = ctx.getImageData(0, 0, ancho, alto);
  const codigo = window.jsQR(imagen.data, ancho, alto, { inversionAttempts: "attemptBoth" });
  return codigo && codigo.data ? codigo.data : null;
}

async function iniciarCamara() {
  if (!navigator.mediaDevices?.getUserMedia) {
    mostrarMensaje($("#mensaje-escaneo"), "La cámara necesita HTTPS. Usa «Subir una imagen» o abre el sitio con https://.", "alerta");
    return;
  }
  try {
    flujo = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
  } catch {
    mostrarMensaje($("#mensaje-escaneo"), "No se pudo usar la cámara (¿permiso denegado?). Prueba subiendo una imagen.", "alerta");
    return;
  }
  video.srcObject = flujo;
  await video.play();
  $("#visor").classList.remove("oculto");
  $("#boton-detener").classList.remove("oculto");
  $("#boton-camara").classList.add("oculto");
  mostrarMensaje($("#mensaje-escaneo"), "Apunta al código QR…");
  requestAnimationFrame(buscarEnVideo);
}

function detenerCamara() {
  if (flujo) flujo.getTracks().forEach((t) => t.stop());
  flujo = null;
  video.srcObject = null;
  $("#visor").classList.add("oculto");
  $("#boton-detener").classList.add("oculto");
  $("#boton-camara").classList.remove("oculto");
}

function buscarEnVideo() {
  if (!flujo) return;
  if (video.readyState >= 2 && video.videoWidth) {
    const escala = Math.min(1, 960 / Math.max(video.videoWidth, video.videoHeight));
    lienzo.width = Math.round(video.videoWidth * escala);
    lienzo.height = Math.round(video.videoHeight * escala);
    ctx.drawImage(video, 0, 0, lienzo.width, lienzo.height);
    const texto = decodificar(lienzo.width, lienzo.height);
    if (texto) {
      detenerCamara();
      mostrarDestino(texto);
      return;
    }
  }
  requestAnimationFrame(buscarEnVideo);
}

async function leerArchivo(archivo) {
  if (!archivo) return;
  try {
    const bitmap = await createImageBitmap(archivo);
    const escala = Math.min(1, MAX_LADO / Math.max(bitmap.width, bitmap.height));
    lienzo.width = Math.round(bitmap.width * escala);
    lienzo.height = Math.round(bitmap.height * escala);
    ctx.drawImage(bitmap, 0, 0, lienzo.width, lienzo.height);
    bitmap.close();
    const texto = decodificar(lienzo.width, lienzo.height);
    if (texto) mostrarDestino(texto);
    else mostrarMensaje($("#mensaje-escaneo"), "No encontramos un código QR en la imagen. Prueba con una más nítida o recortada.", "alerta");
  } catch {
    mostrarMensaje($("#mensaje-escaneo"), "No se pudo leer esa imagen.", "error");
  }
}

// Muestra el contenido del QR como TEXTO. Si no es un enlace web, no hay nada que analizar.
function mostrarDestino(texto) {
  $("#mensaje-escaneo").replaceChildren();
  $("#mensaje-analisis").replaceChildren();
  $("#seccion-destino").classList.remove("oculto");
  $("#destino-url").textContent = texto.length > 600 ? `${texto.slice(0, 600)}…` : texto;
  destino = null;
  let url = null;
  try {
    url = new URL(texto.trim());
  } catch {
    url = null;
  }
  if (url && (url.protocol === "https:" || url.protocol === "http:")) {
    destino = url.href;
    // hostname viene en ASCII/punycode: un dominio con letras de otro alfabeto se nota.
    $("#destino-host").textContent = url.hostname;
    $("#boton-analizar").disabled = false;
  } else {
    $("#destino-host").textContent = "No es un enlace web";
    $("#boton-analizar").disabled = true;
    mostrarMensaje($("#mensaje-analisis"), "Este QR no contiene un enlace http/https: no hay nada que abrir. Si te pide escribir datos o pagar, desconfía.", "alerta");
  }
  $("#seccion-destino").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analizar() {
  if (!destino) return;
  const boton = $("#boton-analizar");
  boton.disabled = true;
  const cuerpo = { url: destino };
  if ($("#usar-ubicacion").checked) {
    mostrarMensaje($("#mensaje-analisis"), "Obteniendo ubicación aproximada…");
    try {
      const u = await ubicacionAproximada();
      cuerpo.lat = u.lat;
      cuerpo.lon = u.lon;
    } catch (e) {
      mostrarMensaje($("#mensaje-analisis"), `Sin ubicación (${e.message}): se analizará igual, sin consultar el registro de QRs.`, "alerta");
    }
  }
  try {
    const r = await api("/analisis", { metodo: "POST", cuerpo });
    location.assign(r.pagina); // nuestra página de resultado, nunca el destino del QR
  } catch (e) {
    if (esErrorDeAcceso(e)) {
      $("#mensaje-analisis").replaceChildren();
      await exigirAcceso($("main"));
      boton.disabled = false;
      return analizar();
    }
    mostrarMensaje($("#mensaje-analisis"), `No se pudo iniciar el análisis: ${e.message}`, "error");
    boton.disabled = false;
  }
}

$("#boton-camara").addEventListener("click", iniciarCamara);
$("#boton-detener").addEventListener("click", detenerCamara);
$("#archivo").addEventListener("change", (e) => leerArchivo(e.target.files[0]));
$("#boton-analizar").addEventListener("click", analizar);
$("#boton-otro").addEventListener("click", () => {
  $("#seccion-destino").classList.add("oculto");
  window.scrollTo({ top: 0, behavior: "smooth" });
});
$("#form-manual").addEventListener("submit", (e) => {
  e.preventDefault();
  const texto = $("#manual").value.trim();
  if (texto) mostrarDestino(texto);
});
exigirAcceso($("main"));
registrarServiceWorker();
