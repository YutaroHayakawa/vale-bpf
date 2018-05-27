platform={{platform}}

FreeBSD_all: FreeBSD_vale_bpf
FreeBSD_clean: FreeBSD_clean
Linux_all: Linux_vale_bpf
Linux_clean: Linux_clean

FreeBSD_vale_bpf:
	make -C sys/modules/vale-bpf

FreeBSD_clean:
	make -C sys/modules/vale-bpf clean

Linux_vale_bpf:
	make -C Linux

Linux_clean:
	make -C Linux clean
