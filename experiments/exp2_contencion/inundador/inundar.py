"""Worker COMPROMETIDO que intenta tumbar al orquestador por su salida (Experimento 2).

Reemplaza al worker real (misma imagen base): en vez de navegar, escupe por stdout
cientos de miles de eventos válidos, líneas gigantes y basura, lo más rápido posible.
"""
import json
import sys

salida = sys.stdout
for i in range(300_000):
    salida.write(json.dumps({"tipo": "request_tercero", "t_ms": 1, "dominio": f"d{i}.test"}) + "\n")
    if i % 1000 == 0:
        salida.write('{"tipo":"error","t_ms":1,"mensaje":"' + "A" * 500_000 + '"}\n')  # línea gigante
        salida.write("{basura no json\n")
salida.write(json.dumps({"tipo": "fin", "t_ms": 2, "resultado": None}) + "\n")
salida.flush()
