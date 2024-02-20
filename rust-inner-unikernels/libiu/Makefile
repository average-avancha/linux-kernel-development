LINUX ?= $(HOME)/linux

CXX = g++
LD = g++
AR = gcc-ar

INC += -I${LINUX}/tools/lib -I${LINUX}/tools/include -I${LINUX}/usr/include
INC += -I${LINUX}/tools/include/uapi

CXXFLAGS += -O2 -march=x86-64 -pipe -std=gnu++17 -fPIC -fno-exceptions
CXXFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
CXXFLAGS += -flto=auto -ffat-lto-objects -fuse-linker-plugin

LDFLAGS += -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections
EXTRA_LDFLAGS += -L${LINUX}/tools/lib/bpf -lbpf -lelf

all: libiu.a libiu.so

libiu.a: libiu.o
	+${AR} rcs $@ $<

libiu.so: libiu.o
	+${LD} ${CXXFLAGS} ${LDFLAGS} -shared -o $@ $< ${EXTRA_LDFLAGS}

libiu.o: libiu.cpp libiu.h
	+${CXX} ${INC} ${CXXFLAGS} -o $@ -c libiu.cpp

clean:
	rm -f libiu.o libiu.a libiu.so
