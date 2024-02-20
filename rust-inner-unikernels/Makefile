BASE_PROJ ?= $(shell pwd)
LINUX ?= ${BASE_PROJ}/linux
USER_ID ?= "$(shell id -u):$(shell id -g)"
SSH_PORT ?= "52222"
.ALWAYS:

NPROCS := 1
OS := $(shell uname)
export NPROCS

ifeq ($J,)

ifeq ($(OS),Linux)
  NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
else ifeq ($(OS),Darwin)
  NPROCS := $(shell sysctl -n hw.ncpu)
endif # $(OS)

else
  NPROCS := $J
endif

all: vmlinux libbpf iu iu-examples

qemu-run: 
	docker run --privileged --rm \
	--device=/dev/kvm:/dev/kvm --device=/dev/net/tun:/dev/net/tun \
	-v ${BASE_PROJ}:/inner_unikernels -v ${LINUX}:/linux \
	-w /linux \
	-p 127.0.0.1:${SSH_PORT}:52222 \
	-it mp4:latest \
	/inner_unikernels/q-script/yifei-q -s

# mapping the gdb port 1234 from docker container 
qemu-run-gdb: 
	docker run --privileged --rm \
	--device=/dev/kvm:/dev/kvm --device=/dev/net/tun:/dev/net/tun \
	-v ${BASE_PROJ}:/inner_unikernels -v ${LINUX}:/linux \
	-w /linux \
	-p 127.0.0.1:${SSH_PORT}:52222 \
	-p 127.0.0.1:1234:1234 \
	-it mp4:latest \
	/inner_unikernels/q-script/yifei-q -s

# connect running qemu by ssh
qemu-ssh:
	ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -t root@127.0.0.1 -p ${SSH_PORT}

libbpf: 
	docker run --rm -u ${USER_ID} -v ${LINUX}:/linux -w /linux/tools/lib/bpf mp4 make -j${NPROCS}

libbpf-clean:
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/lib/bpf mp4 make clean 

vmlinux: 
	docker run --rm -u ${USER_ID} -v ${LINUX}:/linux -w /linux mp4 make -j${NPROCS} bzImage 

linux-clean:
	docker run --rm -v ${LINUX}:/linux -w /linux mp4 make clean

# Target to enter docker container
enter-docker:
	docker run --rm -u ${USER_ID}  -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels -it mp4 /bin/bash

# Might not be needed anymore
iu: 
	docker run --network=host --rm -u ${USER_ID} -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/libiu mp4 make

iu-clean: 
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/libiu mp4 make clean

iu-examples: 
	docker run --network=host -u ${USER_ID} --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/hello mp4 make
	docker run --network=host -u ${USER_ID} --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/map_test mp4 make

mp4-sample:
	docker run --network=host -u ${USER_ID} --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/mp4-sample mp4 make

ebpf-xdp-blocker:
	docker run --network=host -u ${USER_ID} --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/ebpf_xdp_blocker mp4 make


