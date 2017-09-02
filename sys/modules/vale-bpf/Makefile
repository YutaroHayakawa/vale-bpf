.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/vale-bpf

TARGET! = uname -m
IDENT!  = uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../
CFLAGS += -DVALE_NAME=\"$(VALE_NAME)\"

KMOD    = vale-bpf-$(VALE_NAME)
SRCS    += vale_bpf.c

.include <bsd.kmod.mk>
