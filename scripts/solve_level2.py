#!/usr/bin/env python3
"""Reconstruye la clave de crackme_level2 a partir de los datos de .rodata.

Lógica encontrada en validate_key:
    (clave[i] XOR k[i % 4]) debe ser igual a expected[i]
Como XOR se deshace a sí mismo:
    clave[i] = expected[i] XOR k[i % 4]
"""

# Bytes copiados de: objdump -s -j .rodata crackme_level2
k = bytes.fromhex("2351176a")                              # k.1 @ 0x40208b
expected = bytes.fromhex("651544230e03523c6603442f0e63275815")  # expected.0 @ 0x402090

clave = bytes(e ^ k[i % 4] for i, e in enumerate(expected))
print(clave.decode())
