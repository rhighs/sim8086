CXX:=tcc

more-movs-db:
	$(CXX) *.c -g -DDEBUG -o cpu
more-movs:
	$(CXX) *.c -o cpu && ./cpu ./samples/listing_0039_more_movs
more-movs-d:
	$(CXX) *.c -g -DDEBUG -o cpu && ./cpu ./samples/listing_0039_more_movs
