set disassembly-flavor intel
set pagination off
target remote :1234
break validate_key
continue
x/s $rdi
echo \n### Arreglos k y expected en memoria\n
x/4xb  0x40208b
x/17xb 0x402090
echo \n### Breakpoint en el XOR, primeras 4 vueltas del ciclo\n
break *0x4011b9
continue
printf "i=%d  letra(ecx)=0x%02x '%c'  k[i%%4](eax)=0x%02x\n", *(long*)($rbp-0x10), $ecx, $ecx, $eax
continue
printf "i=%d  letra(ecx)=0x%02x '%c'  k[i%%4](eax)=0x%02x\n", *(long*)($rbp-0x10), $ecx, $ecx, $eax
continue
printf "i=%d  letra(ecx)=0x%02x '%c'  k[i%%4](eax)=0x%02x\n", *(long*)($rbp-0x10), $ecx, $ecx, $eax
continue
printf "i=%d  letra(ecx)=0x%02x '%c'  k[i%%4](eax)=0x%02x\n", *(long*)($rbp-0x10), $ecx, $ecx, $eax
delete 2
echo \n### Al terminar el ciclo: score (diferencias acumuladas)\n
break *0x4011e7
continue
printf "score = %d\n", *(int*)($rbp-0x4)
echo \n### Valor de retorno de validate_key\n
finish
info registers rax
continue
