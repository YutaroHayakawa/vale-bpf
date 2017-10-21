SRC_DIR:=../sys/dev/vale-bpf-native

vale-bpf-native-$(VALE_NAME)-objs := $(SRC_DIR)/vale_bpf_native.o

obj-m:=vale-bpf-native-$(VALE_NAME).o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-O3 \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-DCONFIG_NETMAP \
	-DCONFIG_NETMAP_VALE \
	-std=gnu11 -Wno-declaration-after-statement \
	-I$(CURDIR)/../sys \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys \
	-I$(PWD)

EXTRA_SYMBOLS:= \
	$(NSRC)/Module.symvers

all:
ifeq ($(VALE_NAME),)
	@echo "Please specify VALE_NAME variable like VALE_NAME=vale0"
else
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS='$(EXTRA_SYMBOLS)' modules
endif

install_headers:
	ln -s $(CURDIR)/../sys/net/vale_bpf_common.h \
		$(LINUX_SRC)/include/uapi/linux/vale_bpf_common.h
	ln -s $(CURDIR)/../sys/net/vale_bpf_native.h \
		$(LINUX_SRC)/include/uapi/linux/vale_bpf_native.h

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd

clean_headers:
	unlink $(LINUX_SRC)/include/uapi/linux/vale_bpf_common.h
	unlink $(LINUX_SRC)/include/uapi/linux/vale_bpf_native.h
