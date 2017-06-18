CC := $(EBPFCC)
CFLAGS := -I../../ebpf_include -O3 -target bpf -c

all: \
	ip_decrement_ttl \
	rewrite_mac \
	external_function_call \
	hash64_test

ip_decrement_ttl:
	$(CC) $(CFLAGS) ip_decrement_ttl.c

rewrite_mac:
	$(CC) $(CFLAGS) rewrite_mac.c

external_function_call:
	$(CC) $(CFLAGS) external_function_call.c

hash64_test:
	$(CC) $(CFLAGS) hash64_test.c

clean:
	rm *.o *.s
