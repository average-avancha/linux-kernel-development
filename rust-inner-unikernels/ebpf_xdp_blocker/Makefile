LINUX_PATH ?= ../linux

LINUX_INC = ${LINUX_PATH}/usr/include
LIBBPF_DIR = ${LINUX_PATH}/tools/lib/bpf

TARGETS += blocker

CLANG ?= clang
LLC ?= llc
CC := clang

KERN_SOURCES = ${TARGETS:=_kern.c}
USER_SOURCES = ${TARGETS:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

CFLAGS += -O2 -march=native -pipe -std=gnu11
CFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
LDFLAGS += -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections

LOADER_INC += -I${LINUX_INC} -I${LIBBPF_DIR}
LOADER_LDFLAGS = -L${LIBBPF_DIR} -lbpf -lz -lelf

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')

LINUXINCLUDE := -I$(LINUX_PATH)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/include
LINUXINCLUDE += -I$(LINUX_PATH)/include/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/tools/testing/selftests/bpf
LINUXINCLUDE += -I$(LINUX_PATH)/tools/lib
LINUXINCLUDE += -include $(LINUX_PATH)/include/linux/kconfig.h
LINUXINCLUDE += -include $(LINUX_PATH)/samples/bpf/asm_goto_workaround.h
override EXTRA_CFLAGS += -Werror

all: $(TARGETS) $(KERN_OBJECTS)


$(KERN_OBJECTS): %.o: %.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__  -DKBUILD_MODNAME="\"mp4\"" \
	    -D__TARGET_ARCH_$(ARCH) -fno-stack-protector \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-address-of-packed-member \
	    -O3 -g -emit-llvm -c $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(TARGETS): %: %_user.c
	${CC} ${LOADER_INC} ${CFLAGS} -o $@ $< ${LOADER_LDFLAGS} ${LDFLAGS}

clean:
	@find . -type f \
		\( -name '*~' \
		-o -name '*.ll' \
		-o -name '*.bc' \
		-o -name 'core' \) \
		-exec rm -vf '{}' \;
	rm -f $(TARGETS)
	rm -f $(KERN_OBJECTS)
	rm -f $(USER_OBJECTS)
	rm -f $(OBJECT_LOADBPF)

