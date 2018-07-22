# VALE BPF Extension Module
VALE-BPF module is an extension of VALE software switch.

This module makes VALE possible to program with eBPF. It uses generic-ebpf as
a backend eBPF system. It may works on the platform which both of generic-ebpf and
netmap are supported.

## Requirements
- [generic-ebpf](https://github.com/YutaroHayakawa/generic-ebpf.git)
- [netmap](https://github.com/luigirizzo/netmap.git)

## Installation

Assume you already installed netmap and generic-ebpf on your system.
Please see the documentation of them for more details.

### Create VALE

Create switch named vale0 and attach two interfaces

```
# vale-ctl -n vi0 //interface 0
# vale-ctl -n vi1 //interface 1
# vale-ctl -a vale0:vi0 //attach interface 0 to vale0
# vale-ctl -a vale0:vi1 //attach interface 1 to vale0
```

### Install vale-bpf

```
$ make
# make load
```

### Loading eBPF program
Now module is loaded to vale0. However, eBPF program is not yet loaded.
You need to load eBPF program. Below is an example of running sample application.

```
$ cd apps/l2_bridge
# ./l2_bridge -v vale0
```
