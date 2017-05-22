.PATH: ${.CURDIR}/../../dev/vale-bpf

KMOD    = vale-bpf
SRCS    += ebpf.h
SRCS    += vale_bpf_bsd_glue.h
SRCS    += vale_bpf_extern_func.h
SRCS    += vale_bpf_int.h
SRCS    += vale_bpf_kern.h
SRCS    += vale_bpf_limits.h
SRCS    += vale_bpf_loader.c
SRCS    += vale_bpf_main.c
SRCS    += vale_bpf_vm.c

.include <bsd.kmod.mk>
