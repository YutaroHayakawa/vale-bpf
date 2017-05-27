.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/vale-bpf

TARGET! = uname -m
IDENT!  = uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../dev/vale-bpf
CFLAGS += -I../../net
CFLAGS += -DVALE_NAME=\"$(VALE_NAME)\"

KMOD    = vale-bpf-$(VALE_NAME)
SRCS    += ebpf.h
SRCS    += vale_bpf_bsd_glue.h
SRCS    += vale_bpf_extern_func.h
SRCS    += vale_bpf_int.h
SRCS    += vale_bpf_kern.h
SRCS    += vale_bpf_limits.h
SRCS    += vale_bpf_freebsd.c
SRCS    += vale_bpf_loader.c
SRCS    += vale_bpf_main.c
SRCS    += vale_bpf_vm.c
SRCS    += vale_bpf_jit_x86_64.h
SRCS    += vale_bpf_jit_x86_64.c

.include <bsd.kmod.mk>

install:
	kldload ./vale-bpf-$(VALE_NAME).ko
