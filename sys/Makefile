vale-bpf-objs := \
		vale_bpf_loader.o \
		vale_bpf_vm.o \
		vale_bpf_main.o

obj-m := vale-bpf.o

LINUX_SRC := /lib/modules/`uname -r`/build

EXTRA_CFLAGS := \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-I$(CURDIR) \
	-I$(CURDIR)/../include \
	-std=gnu11 -Wno-declaration-after-statement \
	-DCONFIG_NETMAP -DCONFIG_NETMAP_VALE \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys

all:
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers modules

install:
	insmod $(M)/vale-bpf.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
