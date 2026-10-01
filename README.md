# FDSI — Lab 04 Parte 2: Reverse Engineering CTF

Ruta alternativa local del Lab 04: análisis de tres crackmes ELF x86-64 sin código fuente.

## Resultados

| Nivel | Binario | Clave | FLAG |
|---|---|---|---|
| 🟢 Level 1 – Recon | `crackme_level1` | `REDTEAM-101` | `FLAG{strings_are_evidence}` |
| 🟡 Level 2 – Reverse Engineering | `crackme_level2` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` |
| 🔴 Boss – Stripped | `crackme_level2_stripped` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` |

## Estructura

```
docs/evidence/reverse/
├── baseline.txt        # file, sha256sum, readelf -h, símbolos
├── level1.md           # Nivel 1: hipótesis → evidencia → resultado
├── level2.md           # Nivel 2: análisis de validate_key + pseudocódigo propio
├── gdb.md              # Confirmación dinámica con GDB
├── gdb_logs/           # Salida completa de cada sesión de GDB
└── screenshots/        # Capturas (terminal, Ghidra, GDB)
scripts/
├── solve_level2.py     # Invierte el XOR para reconstruir la clave
├── gdb_run.sh          # Lanza binario bajo QEMU + GDB (Docker en Mac ARM)
└── gdb_*.gdb           # Comandos de GDB usados en cada prueba
bin/                    # Binarios entregados por el docente (hash verificado)
reverse-analysis.md     # Informe general, Boss Level, preguntas y guion de exposición
```

## Cómo reproducir

```bash
# 1. Contenedor Linux x86-64 (en Mac ARM se emula)
docker run -d --name revlab --platform linux/amd64 -v "$PWD":/lab -w /lab ubuntu:24.04 sleep infinity
docker exec revlab bash -c "apt-get update && apt-get install -y binutils gdb file qemu-user"

# 2. Baseline y ejecución
docker exec -w /lab/bin revlab sha256sum crackme_level1 crackme_level2 crackme_level2_stripped
docker exec -w /lab/bin revlab ./crackme_level1 REDTEAM-101
docker exec -w /lab/bin revlab ./crackme_level2 FDSI-REVERSE-2026

# 3. Reconstruir la clave del Nivel 2
python3 scripts/solve_level2.py

# 4. GDB (vía QEMU gdbstub)
docker exec -w /lab/bin revlab ../scripts/gdb_run.sh ./crackme_level2 ../scripts/gdb_level2_good.gdb FDSI-REVERSE-2026
```

## Herramientas

`file`, `sha256sum`, `strings`, `readelf`, `nm`, `objdump`, Ghidra, GDB, QEMU user-mode, Python 3.

## Alcance

Binarios académicos entregados por el docente para esta práctica. No se usó ni se solicitó el código fuente.
