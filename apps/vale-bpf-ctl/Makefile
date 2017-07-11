CFLAGS := -I../../sys

vale-bpf-ctl: vale-bpf-ctl.c
	$(CC) -o vale-bpf-ctl $(CFLAGS) vale-bpf-ctl.c

install: vale-bpf-ctl
	cp vale-bpf-ctl /usr/local/bin

clean:
	rm vale-bpf-ctl
