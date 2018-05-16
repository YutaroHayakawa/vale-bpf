CFLAGS = \
	-I ../../sys \

all: learning_bridge.o learning_bridge_loader

learning_bridge.bpf.o: learning_bridge.bpf.c
	clang38 $(CFLAGS) -O3 -target bpf -c learning_bridge.bpf.c

learning_bridge_loader: learning_bridge.o learning_bridge_loader.c
	$(CC) $(CFLAGS) -O0 -g -o $@ learning_bridge_loader.c -lgbpf -lelf


clean:
	- rm learning_bridge.bpf.o
