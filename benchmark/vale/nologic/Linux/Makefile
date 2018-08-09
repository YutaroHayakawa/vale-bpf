BASE:=	../../../..
LINUX_SRC:=/lib/modules/$(shell uname -r)/build

nologic-$(VALE_NAME)-objs:=../nologic.o
obj-m:=nologic-$(VALE_NAME).o

EXTRA_CFLAGS:= \
	-Ofast \
	-D_KERNEL \
	-DVALE_NAME=\"$(VALE_NAME)\" \
	-I$(LINUX_SRC)/include \
	-I$(NSRC) \
	-I$(NSRC)/LINUX \
	-I$(NSRC)/sys

EXTRA_SYMBOLS:= \
	$(NSRC)/Module.symvers

all:
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS='$(EXTRA_SYMBOLS)' modules

install:

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(CURDIR)/modules.order $(CURDIR)/Module.symvers \
		$(CURDIR)/*.o $(CURDIR)/*.ko $(CURDIR)/.*.o.cmd $(CURDIR)/.*.ko.cmd \
		$(CURDIR)/../nologic.o
