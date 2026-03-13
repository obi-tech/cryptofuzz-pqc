all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o deterministic_rng.o
	test $(LIBOQS_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBOQS_A_PATH)
	ar rcs module.a module.o deterministic_rng.o tmp/*
	ranlib module.a

module.o: module.cpp module.h
	test $(LIBOQS_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBOQS_INCLUDE_PATH) -fPIC -c module.cpp -o module.o

deterministic_rng.o: deterministic_rng.cpp deterministic_rng.h
	$(CXX) $(CXXFLAGS) -I $(LIBOQS_INCLUDE_PATH) -fPIC -c deterministic_rng.cpp -o deterministic_rng.o

clean:
	rm -rf *.o module.a tmp/
