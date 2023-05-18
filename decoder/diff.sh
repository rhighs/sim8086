#!/bin/bash
gcc *.c -o decoder && ./decoder $1 > out.asm && nasm out.asm
diff out $1 && rm out out.asm cpu
