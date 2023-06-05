CXX:=gcc
BIN:=sim8086

all:
	$(CXX) -std=c11 -O3 src/*.c -o sim8086

debug:
	$(CXX) -std=c11 src/*.c -g -DDEBUG -o sim8086
