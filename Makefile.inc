.CURDIR?=	$(PWD)
UNAME_s!=	uname -s

KMODLOAD_FreeBSD=	kldload
KMODUNLOAD_FreeBSD=	kldunload
KMODLOAD_Linux=		insmod
KMODUNLOAD_Linux=	rmmod
KMODLOAD=	$(KMODLOAD_$(UNAME_s))
KMODUNLOAD=	$(KMODUNLOAD_$(UNAME_s))

CC?=		cc

VALE_BPF_KMODDIR?=	${BASE}/${UNAME_s}
APPS_DIR=	${BASE}/apps
BENCHMARK_DIR=	${BASE}/benchmark

DEBUG_FLAGS=	-g

VALE_NAME?=	vale0

CFLAGS+=	${DEBUG_FLAGS}

MAKE_CMD=	env ${MAKE_ENV} ${MAKE} ${.MAKEFLAGS} ${MAKE_ARGS}

all:
clean:
	rm -f ${CLEANFILES}
.PHONY:	all clean
