# VALE BPF Extension Module
VALE-BPF module is an extension of VALE software switch.

This module makes VALE possible to program with eBPF.

## Supported Platforms
- Linux (Linux Native)
- FreeBSD

### Experimental Linux native eBPF support

We have experimental support for Linux's native eBPF(vale-bpf-native). Unlike our generic-ebpf, it can be integrated with
other Linux's eBPF functionality like map, tail-call or object pinning and even with bcc toolchains.
It's eBPF context struct (struct vale\_bpf\_md) is binary compatible with XDP's one. So, we can reuse
verifier and (almost all) helper functions for XDP.

#### Defference between XDP program and vale-bpf-native program

XDP program returns "actions" which is like XDP\_DROP or XDP\_TX, 
vale-bpf-native program returns "destination switch port number"

## Requirements

- generic-ebpf (https://github.com/YutaroHayakawa/generic-ebpf.git)
  - don't need for Linux Native target
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

### Install generic-ebpf (for FreeBSD and Linux target)

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

### Install vale-bpf (for FreeBSD and Linux target)

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

### Loading eBPF program (for FreeBSD and Linux target)
Now module is loaded to vale0. However, eBPF program is not yet loaded.
You need to load eBPF program. For that, you can use apps/prog-loader/prog-loader.c

```
$ cd apps/prog-loader
$ make
$ ./prog-loader -s vale0: -p <path to your own eBPF program> -j(enable this flag if you want to use jit)
```

Some example eBPF programs are available in apps/ebpf\_example. Please feel free to
use that.

### Install vale-bpf-native (for Linux Native target)

```
$ export NSRC=<path to your netmap source>
$ export VALE_NAME=vale0
$ git clone https://github.com/YutaroHayakawa/vale-bpf.git
$ cd vale-bpf/LINUX-NATIVE
$ make
# insmod vale-bpf-native-vale0.ko
```

### Loading eBPF program (for Linux Native target)

Recommend to install bcc(https://github.com/iovisor/bcc). Please see their
[installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

```
$ cd apps/linux-native-apps
# python prog-loader.py -a -s vale0: -p <your eBPF program source> -f <your eBPF function name> -t(enable this flag if you use tracing)
```
