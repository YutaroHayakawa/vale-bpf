CFLAGS += \
	-I ../../sys \
	-O3

all: learning_bridge.o learning_bridge_loader

learning_bridge.o: learning_bridge.bpf.c
	clang $(CFLAGS) -O3 -target bpf -c learning_bridge.bpf.c

learning_bridge_loader: learning_bridge.o learning_bridge_loader.c
	$(CC) $(CFLAGS) -O0 -g -o $@ learning_bridge_loader.c -lgbpf -lelf

clean:
	- rm -f learning_bridge.bpf.o learning_bridge_loader
