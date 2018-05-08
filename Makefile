CC := gcc
CXX := g++

CFLAGS := -g -Wall -O3 -DLINUX
CXXFLAGS := $(CFLAGS) -std=c++1z

LDFLAGS := -Wl,-rpath,bin,-rpath, -lm -L./ \
	-Isrc/libev -lev 	\
	-Isrc/udns -ludns	\
	-Isrc/logger -llogger	\
	-Isrc/buffer -lbuffer \
	-lstdc++

vpath %.c src
vpath %.cpp src

SOURCES := main.c netutils.c callback.c socks5.c resolve.c optparser.c help.c
SOURCES_CXX := auth.cpp

ssserver: $(SOURCES) auth.o libev.a libudns.a liblogger.a libbuffer.a
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -g -o $@

auth.o: $(SOURCES_CXX)
	$(CXX) $^ $(CXXFLAGS) $(LDFLAGS) -c -o auth.o

libev.a:
	cd src/libev && ./configure && make
	cp src/libev/.libs/libev.a ./

libudns.a:
	cd src/udns && ./configure && make
	cp src/udns/libudns.a ./

liblogger.a:
	cd src/logger && make liblogger.a
	cp src/logger/liblogger.a ./

libbuffer.a:
	cd src/buffer && make libbuffer.a
	cp src/buffer/libbuffer.a ./

.PHONY: test
test:
	@./test/test.sh

clean:
	rm -rf ssserver
	rm -rf *.a
	rm -rf *.so

builddebian:
	docker build -t debian:gcc .

rundebian:
	docker run --name ss -p 23456:23456 -v ${PWD}:/app/ -it --rm debian:gcc bash
