# VALE BPF Extention Module
Vale-bpf module is an extention of VALE software switch.

This module makes it possible to program VALE with eBPF.

## Requirements
- clang-3.7 (for compilation of C -> eBPF program)
- netmap (https://github.com/luigirizzo/netmap.git)

netmap supports both FreeBSD and Linux, but this module supports
only Linux **for now**. It will be supported in the future.

## Installation
Assume that you already installed netmap/VALE to your system
and created VALE switch named vale0 by some way.

```
$ git clone <this repo>
$ cd vale-bpf/sys
$ export NSRC=<path to your netmap source>
$ VALE_NAME="vale0" make
$ sudo make install
```

Now module is loaded to vale0. However, eBPF program is not yet loaded.
You need to load eBPF program. For that, you can use apps/prog-loader/prog-loader.c

```
$ cd apps/prog-loader.c
$ make
$ ./prog-loader -s vale0: -p <your own eBPF program> -j(enable this flag if you want to use jit)
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
#include <stdint.h> // uint8_t
#include <_vale_bpf_extern_func.h> // external functions

#define DROP 255
#define BROAD_CAST 254

/*
 * Return value of this function will be a destination port
 * of the packet. Port 255 and 254 are reserved for drop and
 * broadcast (to all ports except incoming port).
 *
 * You can use any function name.
 *
 * - buf: pointer to the packet
 */
uint8_t mylookup(uint8_t *buf) {
  /*
   * You can get packet length or source port by calling external
   * function which is defined in sys/vale_bpf_extern_func.h
   */
  uint16_t pkt_len = get_pkt_len();
  uint8_t sport = get_src_port();
  return DROP;
}
```

## Random Notes
Our eBPF VM codes are almost all based on uBPF(https://github.com/iovisor/ubpf).
Thanks for that.

## License
Copyright 2017, Yutaro Hayakawa. Licensed under the Apache License,
Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0).
