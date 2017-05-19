CC := clang-3.7
CFLAGS := -target bpf -c

all: \
	ip_decrement_ttl \
	rewrite_mac

ip_decrement_ttl:
	$(CC) $(CFLAGS) ip_decrement_ttl.c

rewrite_mac:
	$(CC) $(CFLAGS) rewrite_mac.c

clean:
	rm *.o
