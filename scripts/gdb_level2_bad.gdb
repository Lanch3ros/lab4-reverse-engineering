set disassembly-flavor intel
set pagination off
target remote :1234
break validate_key
continue
echo \n### Argumento recibido en RDI (1er parametro)\n
info registers rdi
x/s $rdi
echo \n### Desensamblado de validate_key\n
disassemble validate_key
echo \n### Parar justo despues de strlen: comparar largo esperado vs real\n
break *0x401176
continue
x/gx $rbp-0x18
info registers rax
echo \n### Salir de la funcion y ver el valor de retorno (RAX)\n
finish
info registers rax
continue
