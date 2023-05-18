CXX:=gcc

build:
	$(CXX) -std=c11 -O3 *.c -o decoder
debug:
	$(CXX) -std=c11 *.c -g -DDEBUG -o decoder
