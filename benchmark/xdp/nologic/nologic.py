#!/usr/bin/env python

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

flags = 0
def usage():
    print("Usage: {0} <in ifdev> <out ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

in_if = sys.argv[1]
out_if = sys.argv[2]

ip = pyroute2.IPRoute()
out_idx = ip.link_lookup(ifname=out_if)[0]

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_DEVMAP(tx_port, 1);

int
xdp_nologic(struct xdp_md *ctx)
{
    return tx_port.redirect_map(0, 0);
}

int
xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
""", cflags=["-w"])

tx_port = b.get_table("tx_port")
tx_port[0] = ct.c_int(out_idx)

in_fn = b.load_func("xdp_nologic", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)

b.attach_xdp(in_if, in_fn, flags)
b.attach_xdp(out_if, out_fn, flags)

print("Running nologic program, hit CTRL+C to stop")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Unloading...")
        break;

b.remove_xdp(in_if, flags)
b.remove_xdp(out_if, flags)
print("done")
