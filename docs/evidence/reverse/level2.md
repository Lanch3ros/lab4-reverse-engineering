# Nivel 2 — Reverse Engineering: reconstruir la validación

**Binario:** `crackme_level2`
**SHA-256:** `8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5`
**Herramientas:** `strings`, `objdump`, `nm`, Ghidra, Python (para invertir la operación)

---

## 1. Observación inicial

```text
$ ./crackme_level2
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
Uso: ./crackme_level2 <license-key>
exit=1

$ ./crackme_level2 AAAA
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
Invalid license.
exit=3
```

El programa pide una **clave de licencia** como argumento. Si la clave es incorrecta, muestra `Invalid license.` y sale con código `3`.

## 2. ¿Funciona `strings` esta vez?

```text
$ strings -n 5 crackme_level2
strlen                 <-- ya no usa strcmp, ahora mide la longitud
License accepted.
Invalid license.
validate_key           <-- nombre de la función que valida
expected               <-- variable "esperado"
transformed            <-- variable "transformado"
score                  <-- variable "puntaje"
candidate              <-- variable "candidato" (la clave del usuario)
reveal_flag            <-- función que muestra la FLAG
```

**No aparece ninguna clave en texto plano.** Sin embargo, los nombres de variables (`expected`, `transformed`, `score`) nos dan una pista: el programa **transforma** cada carácter y lo compara contra un valor **esperado**.

## 3. Hipótesis

> La clave no está guardada tal cual. Está guardada **transformada** en un arreglo `expected`. La función `validate_key` aplica una operación a cada letra que escribe el usuario y la compara contra ese arreglo.

## 4. Análisis estático

### 4.1 Encontrar la función que decide (desde `main`)

En Ghidra: *Symbol Tree → Functions → `main`*. En el decompilador se ve así (resumido):

```c
if (argc != 2) { printf("Uso: ..."); return 1; }
if (validate_key(argv[1]) != 0) {   // <-- aquí se decide todo
    puts("License accepted.");
    reveal_flag();
    return 0;
}
puts("Invalid license.");
return 3;
```

Y en ensamblador (`objdump`):

```asm
4012cd: call validate_key     ; validate_key(argv[1])
4012d2: test eax,eax          ; ¿devolvió 0?
4012d4: je   4012f1           ; si es 0 -> "Invalid license."
4012e5: call reveal_flag      ; si es 1 -> muestra la FLAG
```

### 4.2 Dentro de `validate_key` (dirección `0x401156`)

```asm
; --- Paso A: revisar la longitud ---
401162: mov  QWORD PTR [rbp-0x18],0x11    ; largo esperado = 0x11 = 17
401171: call strlen                       ; largo de la clave del usuario
401176: cmp  [rbp-0x18],rax
40117a: je   401183                       ; si no son iguales -> return 0

; --- Paso B: recorrer cada carácter ---
401183: mov  DWORD PTR [rbp-0x4],0x0      ; score = 0
40118a: mov  QWORD PTR [rbp-0x10],0x0     ; i = 0
401194: ...  movzx eax, BYTE [candidate+i]; c = candidate[i]
4011a8: and  eax,0x3                      ; i & 3  -> lo mismo que i % 4
4011ae: lea  rax,[k.1]                    ; arreglo k (4 bytes)
4011b5: movzx eax, BYTE [k + (i&3)]       ; k[i % 4]
4011b9: xor  eax,ecx                      ; transformed = c XOR k[i%4]
4011be: lea  rdx,[expected.0]             ; arreglo expected (17 bytes)
4011cf: xor  al, transformed              ; expected[i] XOR transformed
4011d5: or   DWORD PTR [rbp-0x4],eax      ; score |= (diferencia)
4011d8: add  QWORD PTR [rbp-0x10],0x1     ; i++
4011e1: cmp  rax,[rbp-0x18]               ; ¿i < 17?
4011e5: jb   401194                       ; repetir

; --- Paso C: resultado ---
4011e7: cmp  DWORD PTR [rbp-0x4],0x0      ; ¿score == 0?
4011eb: sete al                           ; devuelve 1 si score es 0, si no 0
```

**Explicado sencillo:**
- `and eax,0x3` toma el índice y se queda solo con sus dos últimos bits, así que el resultado siempre está entre 0 y 3 (es lo mismo que `i % 4`). Por eso el arreglo `k` de 4 bytes **se repite cíclicamente** (Pista 1 del profesor).
- `xor` es la operación **reversible** (Pista 2 del profesor).
- `x XOR y` da 0 solo si `x == y`. El programa acumula todas las diferencias con `OR` en `score`. Si al final `score` es 0, todas las letras coincidieron.

### 4.3 Los datos: arreglos `k` y `expected` en `.rodata`

`nm` nos da las direcciones: `k.1 = 0x40208b` y `expected.0 = 0x402090`.

```text
$ objdump -s -j .rodata crackme_level2
 402080 64206c69 63656e73 652e0023 51176a00  d license..#Q.j.
 402090 65154423 0e03523c 6603442f 0e632758  e.D#..R<f.D/.c'X
 4020a0 15                                   .
```

| Arreglo | Dirección | Bytes |
|---|---|---|
| `k` (4 bytes) | `0x40208b` | `23 51 17 6a` |
| `expected` (17 bytes) | `0x402090` | `65 15 44 23 0e 03 52 3c 66 03 44 2f 0e 63 27 58 15` |

## 5. Pseudocódigo propio (con nombres que pusimos nosotros)

```c
int validate_key(char *candidate) {
    const unsigned char k[4]         = {0x23, 0x51, 0x17, 0x6a};
    const unsigned char expected[17] = {0x65,0x15,0x44,0x23,0x0e,0x03,0x52,0x3c,
                                        0x66,0x03,0x44,0x2f,0x0e,0x63,0x27,0x58,0x15};
    size_t largo = 17;

    if (strlen(candidate) != largo)
        return 0;                                // largo incorrecto

    int diferencias = 0;                         // "score"
    for (size_t i = 0; i < largo; i++) {
        unsigned char transformado = candidate[i] ^ k[i % 4];
        diferencias |= (expected[i] ^ transformado); // 0 si coinciden
    }
    return diferencias == 0;                     // 1 = clave válida
}
```

## 6. Reconstruir la clave (invertir la operación)

La condición para cada letra es `candidate[i] XOR k[i%4] == expected[i]`.
Como XOR se deshace aplicándolo otra vez, despejamos así:

```
candidate[i] = expected[i] XOR k[i % 4]
```

| i | expected | k[i%4] | resultado | letra |
|---|---|---|---|---|
| 0 | 0x65 | 0x23 | 0x46 | F |
| 1 | 0x15 | 0x51 | 0x44 | D |
| 2 | 0x44 | 0x17 | 0x53 | S |
| 3 | 0x23 | 0x6a | 0x49 | I |
| 4 | 0x0e | 0x23 | 0x2d | - |
| 5 | 0x03 | 0x51 | 0x52 | R |
| 6 | 0x52 | 0x17 | 0x45 | E |
| 7 | 0x3c | 0x6a | 0x56 | V |
| 8 | 0x66 | 0x23 | 0x45 | E |
| 9 | 0x03 | 0x51 | 0x52 | R |
| 10 | 0x44 | 0x17 | 0x53 | S |
| 11 | 0x2f | 0x6a | 0x45 | E |
| 12 | 0x0e | 0x23 | 0x2d | - |
| 13 | 0x63 | 0x51 | 0x32 | 2 |
| 14 | 0x27 | 0x17 | 0x30 | 0 |
| 15 | 0x58 | 0x6a | 0x32 | 2 |
| 16 | 0x15 | 0x23 | 0x36 | 6 |

Script usado: [`scripts/solve_level2.py`](../../../scripts/solve_level2.py)

```text
$ python3 scripts/solve_level2.py
FDSI-REVERSE-2026
```

## 7. Comprobación ejecutando el programa

```text
$ ./crackme_level2 FDSI-REVERSE-2026
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
exit=0

$ ./crackme_level2 FDSI-REVERSE-2025      # una sola letra distinta
Invalid license.
exit=3
```

## 8. Resultado

| Elemento | Valor |
|---|---|
| Función de validación | `validate_key` @ `0x401156` |
| Largo esperado | 17 caracteres |
| Transformación | `candidate[i] XOR k[i % 4]`, con `k = 23 51 17 6a` |
| Clave | `FDSI-REVERSE-2026` |
| **FLAG** | **`FLAG{ghidra_plus_gdb}`** |

> Nota: la FLAG se imprime desde `reveal_flag`, que la guarda cifrada con XOR `0x37`, por eso tampoco aparece en `strings`.

## 9. Lección de desarrollo seguro

"Esconder" la clave con XOR **no es seguridad, es solo ofuscación**. Como el programa trae dentro todo lo necesario para comprobar la clave (el arreglo `k` y el arreglo `expected`), cualquiera puede invertir la operación. Si la validación ocurre en la máquina del usuario, el usuario puede verla y revertirla. Los secretos reales deben validarse en un servidor, o con criptografía de verdad (por ejemplo, firmas digitales de licencias), nunca con una "clave escondida" dentro del programa.

## Capturas (carpeta `screenshots/`)
- `level2_main_ghidra.png`: decompilador de `main` mostrando la llamada a `validate_key`.
- `level2_validate_key_ghidra.png`: `validate_key` con las variables renombradas.
- `level2_rodata_ghidra.png`: los arreglos `k` y `expected` en la vista Listing.
- `level2_flag.png`: terminal con la ejecución exitosa.
