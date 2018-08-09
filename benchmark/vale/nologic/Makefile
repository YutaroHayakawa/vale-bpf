.include <bsd.own.mk>

.PATH: ${.CURDIR}

IDENT!=	uname -i

CFLAGS+=	-I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT)
CFLAGS+=	-I../../
CFLAGS+=	-std=c99
CFLAGS+=	-Wall
CFLAGS+=	-DVALE_NAME=\"$(VALE_NAME)\"

KMOD=	nologic-$(VALE_NAME)

SRCS+=	nologic.c

realinstall:

.include <bsd.kmod.mk>
