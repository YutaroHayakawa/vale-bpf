# VALE BPF Extension Module
VALE-BPF module is an extension of VALE software switch.

This module makes VALE possible to program with eBPF.

## Supported Platforms
### FreeBSD
FreeBSD has native support for netmap/VALE, so we can run vale-bpf only with generic-ebpf install.

For programming, please see examples in **apps/vale-bpf/ebpf-examples**.

### Linux 
Since netmap/VALE and generic-ebpf works for Linux, we can run vale-bpf on Linux.

Please see examples in **apps/vale-bpf**.

## Requirements

### Common
- netmap ([https://github.com/luigirizzo/netmap.git](https://github.com/luigirizzo/netmap.git))
- clang-3.7 or later (for compilation of C -> eBPF program)

### Linux and FreeBSD
- generic-ebpf ([https://github.com/YutaroHayakawa/generic-ebpf.git](https://github.com/YutaroHayakawa/generic-ebpf.git))

## Installation

### Common
#### Install netmap

```
$ git clone https://github.com/luigirizzo/netmap.git
$ cd netmap
$ ./configure
$ make
# make install
```

Create switch named vale0 and attach two interfaces

```
# vale-ctl -n vi0 //interface 0
# vale-ctl -n vi1 //interface 1
# vale-ctl -a vale0:vi0 //attach interface 0 to vale0
# vale-ctl -a vale0:vi1 //attach interface 1 to vale0
```

### FreeBSD and Linux
#### Install generic-ebpf

##### FreeBSD

```
$ git clone https://github.com/YutaroHayakawa/generic-ebpf.git
$ cd generic-ebpf/FreeBSD/kernel
$ make
# kldload ./ebpf.ko
```

##### Linux

```
$ git clone https://github.com/YutaroHayakawa/generic-ebpf.git
$ cd generic-ebpf/LINUX/kernel
$ make
# insmod ebpf.ko
```

#### Install vale-bpf

##### FreeBSD

```
$ export NSRC=<path to your netmap source>
$ export EBPFSRC=<path to your generic-ebpf source>
$ export VALE_NAME=vale0
$ git clone https://github.com/YutaroHayakawa/vale-bpf.git
$ cd vale-bpf/sys/modules
$ make
# kldload ./vale-bpf-vale0.ko
```

##### Linux
```
$ export NSRC=<path to your netmap source>
$ export EBPFSRC=<path to your generic-ebpf source>
$ export VALE_NAME=vale0
$ git clone https://github.com/YutaroHayakawa/vale-bpf.git
$ cd vale-bpf/LINUX
$ make
# insmod ./vale-bpf-vale0.ko
```

#### Loading eBPF program
Now module is loaded to vale0. However, eBPF program is not yet loaded.
You need to load eBPF program. For that, you can use apps/prog-loader/prog-loader.c

```
$ cd apps/prog-loader
$ make
$ ./prog-loader -s vale0: -p <path to your own eBPF program> -j(enable this flag if you want to use jit)
```
