CFLAGS_MODULE += -Wno-declaration-after-statement -Werror
APP_CFLAGS = -std=c11 -pipe -O2 -Werror

# KERNEL_SRC := /lib/modules/$(shell uname -r)/build
KERNEL_SRC := /home/neo/cs423/mp0/linux-5.15.127
SUBDIR := $(PWD)
LOGFILE := $(shell date +"%Y-%m-%-d-%H-%M-%S").log
PID := $(shell echo $$PPID)

CC ?= gcc

.PHONY: clean

all: clean modules monitor work

obj-m:= mp3.o

modules:
	$(MAKE) -Wall -C $(KERNEL_SRC) M=$(SUBDIR) modules

monitor: monitor.c
	$(CC) $(APP_CFLAGS) $< -o $@

work: work.c
	$(CC) $(APP_CFLAGS) $< -o $@

clean:
	rm -f monitor work *~ *.ko *.o *.mod.c Module.symvers modules.order

test_proc: mp3.ko
	insmod mp3.ko
	-	echo "R $(PID)" > /proc/mp3/status
	cat /proc/mp3/status
	sleep 10
	cat /proc/mp3/status
	-	echo "U $(PID)" > /proc/mp3/status
	rmmod mp3.ko
	# dmesg -c

test_char: mp3.ko work monitor
	insmod mp3.ko
	cat /proc/devices
	-	mknod node c 423 0
	nice ./work 1024 R 50000 & nice ./work 1024 R 10000 & ./monitor > /home/neo/cs423/mp0/linux-5.15.127/profile1.data
	rmmod mp3.ko
	# dmesg -c

$(LOGFILE):
	touch $(LOGFILE)

mp3.ko:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules


