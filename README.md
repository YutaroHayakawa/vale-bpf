# VALE BPF Extention Module
Vale-bpf module is an extention of VALE software switch.

This module makes VALE possible to program with eBPF.

## Supported Platforms
- Linux
- FreeBSD

## Requirements
- clang-3.7 or later (for compilation of C -> eBPF program)
- netmap (https://github.com/luigirizzo/netmap.git)

## Installation
Assume that you already installed netmap/VALE to your system
and created VALE switch named vale0 by some way.

### Linux
```
$ git clone <this repo>
$ cd vale-bpf/LINUX
$ export NSRC=<path to your netmap source>
$ VALE_NAME=vale0 make
$ sudo VALE_NAME=vale0 make install
```

### FreeBSD
```
$ git clone <this repo>
$ cd vale-bpf/sys/modules/vale-bpf
$ export NSRC=<path to your netmap source>
$ VALE_NAME=vale0 make
$ sudo VALE_NAME=vale0 make install
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

## eBPF Program Semantics
Our eBPF program loader reads first text section of ELF formatted eBPF program.
Maps are not supported **for now**.

eBPF targeted C code is quite limited. For detailed limitations, there are great documents
at Cillium's page (http://docs.cilium.io/en/latest/bpf/)

But basically, it is okey you just copy and paste below template and edit it.

```C
#include <vale_bpf.h> // uint8_t VALE_BPF_DROP
#include <vale_bpf_ext_common.h> // external functions

/*
 * Return value of this function will be a destination port
 * of the packet. Port 255 and 254 are reserved for drop and
 * broadcast (to all ports except incoming port).
 *
 * You can use any function name.
 *
 * - buf: pointer to the packet
 * - len: packet lengt
 * - sport: incoming switch port
 */
uint8_t mylookup(uint8_t *buf, uint16_t len, uint8_t sport) {
  // edit here
  return VALE_BPF_DROP;
}
```

## Random Notes
Our eBPF VM codes are almost all based on uBPF(https://github.com/iovisor/ubpf).
Thanks for that.

## License
Copyright 2017, Yutaro Hayakawa. Licensed under the Apache License,
Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0).
