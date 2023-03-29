#!/bin/bash
gcc -S main.c && cat main.s && rm main.s
