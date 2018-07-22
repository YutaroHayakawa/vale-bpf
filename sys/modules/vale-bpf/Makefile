.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/vale-bpf

IDENT!=	uname -i

CFLAGS+=	-I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT)
CFLAGS+=	-I../../
CFLAGS+=	-Wall
CFLAGS+=	-std=c99
CFLAGS+=	-DVALE_NAME=\"$(VALE_NAME)\"

KMOD=	vale-bpf-$(VALE_NAME)

SRCS+=	vale_bpf.c
SRCS+=	vale_bpf_freebsd.c

realinstall:
	install vale-bpf-$(VALE_NAME).ko $(DESTDIR)

.include <bsd.kmod.mk>
