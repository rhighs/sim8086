CXX:=gcc

build:
	$(CXX) -std=c11 -O3 src/*.c -o decoder
debug:
	$(CXX) -std=c11 src/*.c -g -DDEBUG -o decoder
