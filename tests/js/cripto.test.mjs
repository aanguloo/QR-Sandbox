// Pruebas del JS del navegador (cripto.js) con Node, contra vectores generados por Python.
// Lo corre tests/test_js.py: VECTORES apunta al JSON y SALIDA a donde escribir resultados.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import {
  canonico, bytesCanonicos, generarClaves, publicaB64, firmar, verificarFirma,
  verificarInclusion, verificarConsistencia, hashHoja, verificarSth, verificarHoja, leerHoja,
  exportarRespaldo, importarRespaldo,
} from "../../web/static/js/cripto.js";
import { hexABytes, bytesAHex } from "../../web/static/js/comun.js";

const V = JSON.parse(readFileSync(process.env.VECTORES, "utf8"));
const enc = new TextEncoder();

test("formato canónico idéntico a Python", () => {
  for (const c of V.canonicos) assert.equal(canonico(c.objeto), c.texto);
});

test("hash de hoja y raíces de Certificate Transparency", async () => {
  for (const c of V.hojas) assert.equal(bytesAHex(await hashHoja(hexABytes(c.datos))), c.hash);
});

test("pruebas de inclusión de Python verifican en JS (y adulteradas no)", async () => {
  for (const c of V.inclusion) {
    const ruta = c.ruta.map(hexABytes);
    assert.ok(await verificarInclusion(c.indice, c.tamano, hexABytes(c.hoja), ruta, hexABytes(c.raiz)), JSON.stringify(c));
    assert.ok(!(await verificarInclusion(c.indice, c.tamano, hexABytes(c.otra), ruta, hexABytes(c.raiz))));
  }
});

test("pruebas de consistencia de Python verifican en JS (y adulteradas no)", async () => {
  for (const c of V.consistencia) {
    const ruta = c.ruta.map(hexABytes);
    assert.ok(await verificarConsistencia(c.m, c.n, hexABytes(c.raiz_m), hexABytes(c.raiz_n), ruta), JSON.stringify(c));
    assert.ok(!(await verificarConsistencia(c.m, c.n, hexABytes(c.otra), hexABytes(c.raiz_n), ruta)));
  }
});

test("firma de Python (registro y STH) se verifica en JS", async () => {
  const r = V.registro_python;
  assert.ok(await verificarFirma(r.registro.clave_publica, bytesCanonicos(r.registro), r.firma));
  const alterado = { ...r.registro, url_destino: "https://malo.cl/" };
  assert.ok(!(await verificarFirma(r.registro.clave_publica, bytesCanonicos(alterado), r.firma)));
  assert.ok(await verificarSth(V.recibo.sth, V.recibo.clave_log));
  assert.ok(await verificarHoja(V.recibo.indice, V.recibo.hoja, V.recibo.prueba_inclusion, V.recibo.sth));
  const hoja = await leerHoja(V.recibo.hoja);
  assert.equal(hoja.tipo, "registro");
  assert.ok(hoja.firmaValida);
});

test("JS firma un registro que Python verificará; respaldo de clave", async () => {
  const par = await generarClaves();
  const registro = { ...V.registro_python.registro, clave_publica: await publicaB64(par) };
  const firma = await firmar(par.privateKey, bytesCanonicos(registro));
  const otroPar = await importarRespaldo(await exportarRespaldo(par));
  const firma2 = await firmar(otroPar.privateKey, bytesCanonicos(registro));
  writeFileSync(process.env.SALIDA, JSON.stringify({ registro, firma, firma2 }));
});
