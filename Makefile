platform={{platform}}

FreeBSD_all: FreeBSD_vale_bpf
Linux_all: Linux_vale_bpf

FreeBSD_vale_bpf:
	make -C sys/modules/vale-bpf

Linux_vale_bpf:
	make -C Linux
