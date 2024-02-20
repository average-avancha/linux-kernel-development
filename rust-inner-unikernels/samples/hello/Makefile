LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

RUST_FLAGS = -Funsafe_code -Clink-arg=-nostartfiles -Ciu-playground
CARGO_FLAGS = -Zbuild-std=core --target x86_64-unknown-linux-gnu

CC = gcc

CFLAGS += -O2 -march=native -pipe -std=gnu11
CFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
LDFLAGS += -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections

LOADER_INC += -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR}
LOADER_LDFLAGS = -L${LIBBPF_DIR} -L${LIBIU_DIR} -lbpf -liu

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

all: target/x86_64-unknown-linux-gnu/release/hello loader event-trigger

target/x86_64-unknown-linux-gnu/debug/hello: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

mir:
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS} --emit=mir

llvm-ir:
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS} --emit=llvm-ir

target/x86_64-unknown-linux-gnu/release/hello: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

loader: loader.c
	${CC} ${LOADER_INC} ${CFLAGS} ${LDFLAGS} -o $@ $< ${LOADER_LDFLAGS}

event-trigger: event-trigger.c
	${CC} -I${LINUX_INC} ${CFLAGS} ${LDFLAGS} -o $@ $<

clean:
	rm -rf loader event-trigger ./src/linux ./src/stub.rs
	cargo clean

vmcopy: target/x86_64-unknown-linux-gnu/release/hello loader
	cp target/x86_64-unknown-linux-gnu/release/hello loader ../../rootfs/guest/
