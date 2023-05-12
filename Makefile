CXX:=gcc

build:
	$(CXX) -std=c11 -O3 *.c -g -DDEBUG -o cpu
debug:
	$(CXX) -std=c11 *.c -g -DDEBUG -o cpu
