vale-bpf-objs := \
		vale_bpf_loader.o \
		vale_bpf_vm.o \
		vale_bpf_jit_x86_64.o \
		vale_bpf_linux.o \
		vale_bpf_hash64.o \
		vale_bpf_main.o

obj-m := vale-bpf.o

LINUX_SRC := /lib/modules/`uname -r`/build

EXTRA_CFLAGS := \
	-O3 \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-I$(CURDIR)/../sys/dev/vale-bpf \
	-I$(CURDIR)/../sys/net \
	-std=gnu11 -Wno-declaration-after-statement \
	-DCONFIG_NETMAP -DCONFIG_NETMAP_VALE \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys

all:
ifeq ($(VALE_NAME),)
	@echo "Please specify VALE_NAME variable like VALE_NAME=vale0"
else
	make -C $(LINUX_SRC) M=$(CURDIR)/../sys/dev/vale-bpf CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers modules
	cp ../sys/dev/vale-bpf/vale-bpf.ko .
endif

vale_bpf_linux.o: $(SOURCE_PATH)/vale_bpf_linux.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)

install:
	insmod ./vale-bpf.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
