set disassembly-flavor intel
set pagination off
target remote :1234
break *0x4011e7
continue
echo \n### Clave de 17 caracteres pero con UNA letra distinta\n
printf "score = 0x%x  (distinto de 0 -> clave invalida)\n", *(int*)($rbp-0x4)
stepi
stepi
info registers rax
continue
