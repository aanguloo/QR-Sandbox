"""Genera el perfil seccomp del worker a partir del perfil por defecto de Docker.

    python scripts/generar_seccomp.py

Base: docker/worker/seccomp/docker-default.json (copia de
https://github.com/moby/profiles/blob/main/seccomp/default.json, para reproducibilidad).

Idea: el perfil de Docker es genérico (debe servir a cualquier contenedor). El worker
solo ejecuta Chromium + Python, así que quitamos syscalls que permiten inspeccionar o
manipular otros procesos, o que son superficie de ataque histórica del kernel.
Lo que no está permitido devuelve EPERM (defaultAction del perfil base).
"""

import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
BASE = RAIZ / "docker/worker/seccomp/docker-default.json"
SALIDA = RAIZ / "src/qrsandbox/orquestador/seccomp_worker.json"

# syscall -> motivo (va al informe).
QUITAR = {
    "ptrace": "depurar/inyectar código en otros procesos",
    "process_vm_readv": "leer memoria de otro proceso",
    "process_vm_writev": "escribir memoria de otro proceso",
    "kcmp": "comparar recursos del kernel entre procesos (info leak)",
    "pidfd_getfd": "robar descriptores de otro proceso",
    "name_to_handle_at": "handles de archivos (base de escapes tipo 'shocker')",
    "open_by_handle_at": "idem: abrir archivos por handle saltándose el path",
    "userfaultfd": "primitiva frecuente en exploits de carreras del kernel",
    "perf_event_open": "superficie de ataque del kernel y canal lateral",
    "bpf": "cargar programas en el kernel",
    "keyctl": "keyring del kernel (no se usa, superficie histórica)",
    "add_key": "idem",
    "request_key": "idem",
    "io_uring_setup": "io_uring: gran fuente de CVEs de escalamiento",
    "io_uring_enter": "idem",
    "io_uring_register": "idem",
    "lookup_dcookie": "no necesario",
    "acct": "no necesario",
    "quotactl": "no necesario",
    "syslog": "leer el log del kernel (info leak)",
}


def generar() -> dict:
    perfil = json.loads(BASE.read_text())
    reglas = []
    for regla in perfil["syscalls"]:
        if regla["action"] == "SCMP_ACT_ALLOW":
            nombres = [n for n in regla["names"] if n not in QUITAR]
            if not nombres:
                continue
            regla = {**regla, "names": nombres}
        reglas.append(regla)
    perfil["syscalls"] = reglas
    return perfil


if __name__ == "__main__":
    SALIDA.write_text(json.dumps(generar(), indent=1) + "\n")
    print(f"escrito {SALIDA.relative_to(RAIZ)} (quitadas {len(QUITAR)} syscalls)")
