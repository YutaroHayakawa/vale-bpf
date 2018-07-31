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
b = BPF(src_file="l2_bridge.bpf.c", cflags=["-w"])

in_fn = b.load_func("xdp_l2_bridge", BPF.XDP)
out_fn = b.load_func("xdp_l2_bridge", BPF.XDP)

b.attach_xdp(in_if, in_fn, flags)
b.attach_xdp(out_if, out_fn, flags)

print("Running l2_bridge program, hit CTRL+C to stop")

while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Unloading...")
        break;

b.remove_xdp(in_if, flags)
b.remove_xdp(out_if, flags)
print("done")
