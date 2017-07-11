SRC_DIR:=../sys/dev/vale-bpf

vale-bpf-$(VALE_NAME)-objs := \
	$(SRC_DIR)/vale_bpf_loader.o \
	$(SRC_DIR)/vale_bpf_vm.o \
	$(SRC_DIR)/vale_bpf_jit_x86_64.o \
	vale_bpf_linux.o \
	$(SRC_DIR)/vale_bpf_main.o

obj-m:=vale-bpf-$(VALE_NAME).o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-O3 \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-I$(CURDIR)/../sys/dev/vale-bpf \
	-I$(CURDIR)/../sys/net \
	-std=gnu11 -Wno-declaration-after-statement \
	-DCONFIG_NETMAP -DCONFIG_NETMAP_VALE \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys \
	-I$(PWD)

all:
ifeq ($(VALE_NAME),)
	@echo "Please specify VALE_NAME variable like VALE_NAME=vale0"
else
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers modules
endif

vale_bpf_linux.o: ./vale_bpf_linux.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)

install:
	insmod ./vale-bpf-$(VALE_NAME).ko

install_headers:
	cp ../sys/net/vale_bpf.h /usr/local/include/net

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd
