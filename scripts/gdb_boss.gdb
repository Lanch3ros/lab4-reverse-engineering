set disassembly-flavor intel
set pagination off
target remote :1234
echo \n### Sin simbolos: break validate_key NO existe\n
break validate_key
echo \n### Breakpoint por DIRECCION en la funcion desconocida (FUN_00401156)\n
break *0x401156
continue
x/s $rdi
echo \n### Breakpoint al final del ciclo: acumulador de diferencias\n
break *0x4011e7
continue
printf "score = %d\n", *(int*)($rbp-0x4)
echo \n### Volver al llamador y ver retorno (RAX)\n
finish
info registers rax
continue
