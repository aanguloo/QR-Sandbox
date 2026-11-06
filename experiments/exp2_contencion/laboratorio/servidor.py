"""Servidor del laboratorio del Experimento 2: páginas hostiles PROPIAS y locales.

Ética: todo corre en nuestra red Docker interna; ninguna página toca infraestructura ajena.
Rutas especiales: /bucle?n=N (redirección HTTP infinita), /archivo.apk (descarga forzada).
"""
import http.server
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

RAIZ = Path(__file__).resolve().parent / "paginas"


class Manejador(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(RAIZ), **kw)

    def do_GET(self):
        partes = urlsplit(self.path)
        if partes.path == "/bucle":
            n = int(parse_qs(partes.query).get("n", ["0"])[0]) + 1
            self.send_response(302)
            self.send_header("Location", f"/bucle?n={n}")
            self.end_headers()
            return
        if partes.path == "/archivo.apk":
            cuerpo = b"PK\x03\x04 archivo de prueba inofensivo"
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Disposition", 'attachment; filename="actualizacion.apk"')
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
            return
        super().do_GET()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Manejador).serve_forever()
