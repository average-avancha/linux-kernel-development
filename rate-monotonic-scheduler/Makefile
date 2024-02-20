KERNEL_SRC:= /home/neo/cs423/mp0/linux-5.15.127
# LOGPATH:= /home/neo/cs423/mp2/testing
# /home/neo/cs423/mp0/linux-5.15.127/mp2_testing/mp2_testx.log
LOGPATH:= $(KERNEL_SRC)/mp2_testing
# LOGFILE= $(LOGPATH)/$(shell date +"%Y-%m-%-d-%H-%M-%S").log
LOGFILE= $(LOGPATH)/mp2.log
SUBDIR= $(PWD)
GCC:=gcc
RM:=rm
PID:= $$

.PHONY : clean

all: clean modules app

obj-m:= mp2.o

modules:
	$(MAKE) -Werror -C $(KERNEL_SRC) M=$(SUBDIR) modules

app: userapp.c userapp.h
	$(GCC) -g -o userapp userapp.c

clean:
	$(RM) -f userapp *~ *.ko *.o *.mod.c Module.symvers modules.order

test: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	./userapp 1000 5 
	sleep 10
	rmmod mp2.ko 
# dmesg -c

test0: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	echo "R,$(PID),1000,500" > /proc/mp2/status
	echo "Y,$(PID)" > /proc/mp2/status 
	sleep 5 
	echo "D,$(PID)" > /proc/mp2/status 
	rmmod mp2.ko 


test1: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	./userapp 1000 1 & 
	./userapp 1000 1 &
	./userapp 1000 1 &
	./userapp 1000 1 &
	./userapp 1000 1 &
	sleep 10
	cat /proc/mp2/status
	rmmod mp2.ko 

test2: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	./userapp 1000 6 &
	./userapp 10000 9 &
	./userapp 1000 6 &
	sleep 15
	rmmod mp2.ko 

test3: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	for i in {1..20}; do ./userapp 1000 83 & done
	for i in {1..20}; do ./userapp 500 83 & done
	sleep 120
	rmmod mp2.ko

test_read: mp2.ko userapp $(LOGFILE)
	insmod mp2.ko 
	for i in {1..100}; do ./userapp 1000 83 & done
	cat /proc/mp2/status
	sleep 120
	rmmod mp2.ko

$(LOGFILE):
	mkdir -p $(dir $(LOGFILE))
	touch $(LOGFILE)

mp2.ko:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules