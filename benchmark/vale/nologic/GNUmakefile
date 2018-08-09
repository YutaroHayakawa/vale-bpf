SRC_DIR:=.

nologic-$(VALE_NAME)-objs := $(SRC_DIR)/nologic.o

obj-m:=nologic-$(VALE_NAME).o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-Ofast \
	-D_KERNEL \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-DCONFIG_NETMAP \
	-DCONFIG_NETMAP_VALE \
	-std=gnu99 \
	-Wall \
	-Wno-declaration-after-statement \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys

EXTRA_SYMBOLS:= \
	$(NSRC)/Module.symvers

all:
ifeq ($(VALE_NAME),)
	@echo "Please specify VALE_NAME variable like VALE_NAME=vale0"
else
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS='$(EXTRA_SYMBOLS)' modules
endif

install:

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd
