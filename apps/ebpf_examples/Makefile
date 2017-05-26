CC := $(EBPFCC)
CFLAGS := -I../../ebpf_include -target bpf -c

all: \
	ip_decrement_ttl \
	rewrite_mac \
	external_function_call

ip_decrement_ttl:
	$(CC) $(CFLAGS) ip_decrement_ttl.c

rewrite_mac:
	$(CC) $(CFLAGS) rewrite_mac.c

external_function_call:
	$(CC) $(CFLAGS) external_function_call.c

clean:
	rm *.o
