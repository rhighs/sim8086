#!/bin/bash
tcc *.c -o cpu && ./cpu $1 > out.asm && nasm out.asm
diff out $1 && rm out out.asm cpu
