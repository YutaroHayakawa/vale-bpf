CC := clang-3.7
CFLAGS := -I../../include -target bpf -c

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
