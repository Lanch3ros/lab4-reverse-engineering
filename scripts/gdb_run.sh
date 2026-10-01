#!/bin/bash
# Uso (dentro del contenedor revlab): ./gdb_run.sh <binario> <comandos.gdb> <argumento>
# Lanza el binario bajo QEMU con servidor GDB en :1234 y conecta GDB a él.
# (Necesario porque en Docker sobre Mac ARM, GDB no puede usar ptrace directamente.)
BIN=$1; CMDS=$2; ARG=$3
qemu-x86_64 -g 1234 "$BIN" "$ARG" &
sleep 1
gdb -q -batch -x "$CMDS" "$BIN"
wait
