CXX:=gcc

build:
	$(CXX) -std=c11 -O3 *.c -o cpu
debug:
	$(CXX) -std=c11 *.c -g -DDEBUG -o cpu
