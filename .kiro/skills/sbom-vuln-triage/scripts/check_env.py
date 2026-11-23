#!/usr/bin/env python3
"""Comprueba que el entorno tiene lo necesario: Python, python-docx, lxml y Grype."""
import shutil
import subprocess
import sys

ok = True


def line(name, good, detail):
    global ok
    ok = ok and good
    print(f"[{'OK' if good else 'FALTA'}] {name}: {detail}")


line("Python >= 3.9", sys.version_info >= (3, 9), sys.version.split()[0])
for mod, pkg in (("docx", "python-docx"), ("lxml", "lxml")):
    try:
        m = __import__(mod)
        line(pkg, True, getattr(m, "__version__", "instalado"))
    except ImportError:
        line(pkg, False, "python -m pip install -r requirements.txt")

path = shutil.which("grype")
if not path:
    line("grype", False, "no está en el PATH (ver README, apartado Instalación)")
else:
    out = subprocess.run([path, "version"], capture_output=True, text=True).stdout
    ver = next((l.split()[-1] for l in out.splitlines() if l.startswith("Version")), "?")
    line("grype", True, f"{ver} ({path})")
    db = subprocess.run([path, "db", "status"], capture_output=True, text=True)
    txt = (db.stdout + db.stderr).strip().replace("\n", " | ")
    line("base de datos de grype", db.returncode == 0,
         txt or "sin información; ejecuta 'grype db update' (requiere red)")
print("Entorno correcto" if ok else "Entorno INCOMPLETO")
sys.exit(0 if ok else 1)
