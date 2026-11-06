// Criptografía del QR Transparency Log en el navegador (WebCrypto).
//
// Espejo exacto de src/qrsandbox/tlog/{registro,merkle}.py, para que el usuario NO tenga
// que confiar en el servidor: los recibos, pruebas y firmas se verifican aquí.
// Se prueba con Node contra vectores generados por Python (tests/js/).

import { b64aBytes, bytesAB64, hexABytes } from "./comun.js";

const sutil = globalThis.crypto.subtle;
const ED25519 = { name: "Ed25519" };
const codificador = new TextEncoder();

export const VERSION_REGISTRO = "qrtlog-registro-v1";
export const VERSION_REVOCACION = "qrtlog-revocacion-v1";
export const VERSION_STH = "qrtlog-sth-v1";

// ---------------------------------------------------------------- formato canónico

// JSON con claves en orden alfabético y sin espacios: los mismos bytes que
// json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) en Python.
// (Solo se usan enteros: los floats se serializan distinto en JS y Python.)
export function canonico(valor) {
  if (valor === null || typeof valor !== "object") {
    if (typeof valor === "number" && !Number.isSafeInteger(valor)) throw new Error("solo enteros");
    return JSON.stringify(valor);
  }
  if (Array.isArray(valor)) return `[${valor.map(canonico).join(",")}]`;
  const claves = Object.keys(valor).sort();
  return `{${claves.map((k) => `${JSON.stringify(k)}:${canonico(valor[k])}`).join(",")}}`;
}

export function bytesCanonicos(valor) {
  return codificador.encode(canonico(valor));
}

// ---------------------------------------------------------------- Ed25519

export async function soportaEd25519() {
  try {
    await sutil.generateKey(ED25519, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

export function generarClaves() {
  // Extraíble SOLO para poder exportar un respaldo cuando el usuario lo pida.
  return sutil.generateKey(ED25519, true, ["sign", "verify"]);
}

export async function publicaB64(par) {
  return bytesAB64(await sutil.exportKey("raw", par.publicKey));
}

export async function firmar(privada, bytes) {
  return bytesAB64(await sutil.sign(ED25519, privada, bytes));
}

export async function verificarFirma(publicaBase64, bytes, firmaBase64) {
  try {
    const clave = await sutil.importKey("raw", b64aBytes(publicaBase64), ED25519, false, ["verify"]);
    return await sutil.verify(ED25519, clave, b64aBytes(firmaBase64), bytes);
  } catch {
    return false;
  }
}

export async function exportarRespaldo(par) {
  return {
    v: "qrsandbox-respaldo-clave-v1",
    algoritmo: "Ed25519",
    publica: await publicaB64(par),
    privada_pkcs8: bytesAB64(await sutil.exportKey("pkcs8", par.privateKey)),
    aviso: "Esta es tu clave privada: quien la tenga puede registrar y revocar QRs a tu nombre.",
  };
}

export async function importarRespaldo(respaldo) {
  if (respaldo?.v !== "qrsandbox-respaldo-clave-v1") throw new Error("no es un respaldo de QR-Sandbox");
  const privateKey = await sutil.importKey("pkcs8", b64aBytes(respaldo.privada_pkcs8), ED25519, true, ["sign"]);
  const publicKey = await sutil.importKey("raw", b64aBytes(respaldo.publica), ED25519, true, ["verify"]);
  // Comprueba que la pública corresponda a la privada.
  const prueba = codificador.encode("prueba-de-par");
  if (!(await sutil.verify(ED25519, publicKey, await sutil.sign(ED25519, privateKey, prueba), prueba))) {
    throw new Error("la clave pública no corresponde a la privada");
  }
  return { privateKey, publicKey };
}

// ---------------------------------------------------------------- Merkle (RFC 9162)

async function sha256(...partes) {
  const largo = partes.reduce((n, p) => n + p.length, 0);
  const todo = new Uint8Array(largo);
  let i = 0;
  for (const p of partes) {
    todo.set(p, i);
    i += p.length;
  }
  return new Uint8Array(await sutil.digest("SHA-256", todo));
}

export const hashHoja = (datos) => sha256(Uint8Array.of(0), datos);
export const hashNodo = (izq, der) => sha256(Uint8Array.of(1), izq, der);

function iguales(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// Aritmética con Math.floor y % (no operadores de bits): válida más allá de 2^31.
const bajo = (n) => n % 2 === 1;
const mitad = (n) => Math.floor(n / 2);

export async function verificarInclusion(indice, tamano, hoja, ruta, raiz) {
  if (!(indice >= 0 && indice < tamano)) return false;
  let fn = indice;
  let sn = tamano - 1;
  let r = hoja;
  for (const p of ruta) {
    if (sn === 0) return false;
    if (bajo(fn) || fn === sn) {
      r = await hashNodo(p, r);
      while (!bajo(fn) && fn !== 0) {
        fn = mitad(fn);
        sn = mitad(sn);
      }
    } else {
      r = await hashNodo(r, p);
    }
    fn = mitad(fn);
    sn = mitad(sn);
  }
  return sn === 0 && iguales(r, raiz);
}

export async function verificarConsistencia(tamano1, tamano2, raiz1, raiz2, ruta) {
  if (tamano1 > tamano2 || tamano1 < 0) return false;
  if (tamano1 === tamano2) return ruta.length === 0 && iguales(raiz1, raiz2);
  if (tamano1 === 0) return ruta.length === 0;
  ruta = [...ruta];
  if ((tamano1 & (tamano1 - 1)) === 0) ruta.unshift(raiz1); // potencia de 2
  if (ruta.length === 0) return false;
  let fn = tamano1 - 1;
  let sn = tamano2 - 1;
  while (bajo(fn)) {
    fn = mitad(fn);
    sn = mitad(sn);
  }
  let fr = ruta[0];
  let sr = ruta[0];
  for (const c of ruta.slice(1)) {
    if (sn === 0) return false;
    if (bajo(fn) || fn === sn) {
      fr = await hashNodo(c, fr);
      sr = await hashNodo(c, sr);
      while (!bajo(fn) && fn !== 0) {
        fn = mitad(fn);
        sn = mitad(sn);
      }
    } else {
      sr = await hashNodo(sr, c);
    }
    fn = mitad(fn);
    sn = mitad(sn);
  }
  return iguales(fr, raiz1) && iguales(sr, raiz2) && sn === 0;
}

// ---------------------------------------------------------------- STH y hojas

export function mensajeSth(sth) {
  return bytesCanonicos({ v: VERSION_STH, tamano: sth.tamano, raiz: sth.raiz, timestamp_ms: sth.timestamp_ms });
}

export function verificarSth(sth, claveLog) {
  return verificarFirma(claveLog, mensajeSth(sth), sth.firma);
}

// Verifica que `hojaTexto` (bytes exactos de la hoja) esté en el árbol firmado `sth`.
export async function verificarHoja(indice, hojaTexto, rutaHex, sth) {
  const hoja = await hashHoja(codificador.encode(hojaTexto));
  return verificarInclusion(indice, sth.tamano, hoja, rutaHex.map(hexABytes), hexABytes(sth.raiz));
}

// Decodifica una hoja y verifica la firma del comercio sobre su contenido.
export async function leerHoja(hojaTexto) {
  const d = JSON.parse(hojaTexto);
  const tipo = d.registro ? "registro" : d.revocacion ? "revocacion" : null;
  if (!tipo) throw new Error("hoja desconocida");
  const contenido = d[tipo];
  const firmaValida = await verificarFirma(contenido.clave_publica, bytesCanonicos(contenido), d.firma);
  return { tipo, contenido, firma: d.firma, t_log_ms: d.t_log_ms, firmaValida };
}
