vale-bpf-objs := \
		vale_bpf_loader.o \
		vale_bpf_vm.o \
		vale_bpf_main.o \

obj-m := vale-bpf.o

M := $(CURDIR)
LINUX_SRC := /lib/modules/`uname -r`/build
NSRC := /home/river/netmap

EXTRA_CFLAGS := -I$(LINUX_SRC)/include -std=gnu11 -Wno-declaration-after-statement \
	-I$(NSRC) -I$(NSRC)/LINUX -I$(NSRC)/sys -DCONFIG_NETMAP -DCONFIG_NETMAP_VALE

all:
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers modules
	ls -l `find . -name \*.ko`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
