# VALE BPF Extention Module
VALE-BPF module is an extention of VALE software switch.

This module makes VALE possible to program with eBPF.

## Supported Platforms
- Linux
- FreeBSD

## Requirements
- generic-ebpf (https://github.com/YutaroHayakawa/generic-ebpf.git)
- clang-3.7 or later (for compilation of C → eBPF program)
- netmap (https://github.com/luigirizzo/netmap.git)

## Installation

### Install netmap

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

### Install generic-ebpf

#### FreeBSD

```
$ git clone https://github.com/YutaroHayakawa/generic-ebpf.git
$ cd generic-ebpf/FreeBSD/kernel
$ make
# kldload ./ebpf.ko
```

#### Linux

```
$ git clone https://github.com/YutaroHayakawa/generic-ebpf.git
$ cd generic-ebpf/LINUX/kernel
$ make
# insmod ebpf.ko
```

### Install vale-bpf

#### FreeBSD

```
$ export NSRC=<path to your netmap source>
$ export EBPFSRC=<path to your generic-ebpf source>
$ export VALE_NAME=vale0
$ git clone https://github.com/YutaroHayakawa/vale-bpf.git
$ cd vale-bpf/sys/modules
$ make
$ kldload ./vale-bpf-vale0.ko
```

#### Linux
```
$ export NSRC=<path to your netmap source>
$ export EBPFSRC=<path to your generic-ebpf source>
$ export VALE_NAME=vale0
$ git clone https://github.com/YutaroHayakawa/vale-bpf.git
$ cd vale-bpf/LINUX
$ make
$ insmod ./vale-bpf-vale0.ko
```

### Loading eBPF Program
Now module is loaded to vale0. However, eBPF program is not yet loaded.
You need to load eBPF program. For that, you can use apps/prog-loader/prog-loader.c

```
$ cd apps/prog-loader
$ make
$ ./prog-loader -s vale0: -p <path to your own eBPF program> -j(enable this flag if you want to use jit)
```

Some example eBPF programs are available in apps/ebpf\_example. Please feel free to
use that.

## Random Notes
Our eBPF VM codes are almost all based on uBPF(https://github.com/iovisor/ubpf).
Thanks for that.

## License
Copyright 2017, Yutaro Hayakawa. Licensed under the Apache License,
Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0).
