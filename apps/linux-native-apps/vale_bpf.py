from bcc import BPF
from ctypes import *
import fcntl
from ioctl import IOWR, IOC_WRITE


class NM_IFREQ(Structure):
    _fields_ = [
        ('nifr_name', c_char * 16),
        ('data', c_char * 256)
    ]


class VALE_BPF_REQ(Structure):
    _fields_ = [
        ('vale_name', c_char * 16),
        ('method', c_uint8),
        ('len', c_size_t),
        ('ufd', c_int),
        ('_pad', c_char * (256 - 13))
    ]


class VALE_BPF(BPF):

    INSTALL_PROG=0
    BPF.VALE_BPF = BPF.XDP
    NIOCCONFIG = IOWR(ord('i'), 150, NM_IFREQ)

    def __init__(self, src_file='', hdr_file='',
            text=None, cb=None, debug=0, cflags=[],
            usdt_contexts=[]):
        super(VALE_BPF, self).__init__(src_file, hdr_file,
                text, cb, debug, cflags, usdt_contexts)

    def attach_vale_bpf(self, vale_name, func_name):
        func = self.load_func(func_name, BPF.VALE_BPF)
        vale_name_bytes = bytes(vale_name) + b"\0" * (16 - len(vale_name))

        req = VALE_BPF_REQ(vale_name_bytes,
                           self.INSTALL_PROG,
                           4,
                           func.fd)

        f = open("/dev/netmap", "a+")
        fcntl.ioctl(f, self.NIOCCONFIG, req)

        f.close()

    def remove_vale_bpf(self, vale_name):
        f = open("/dev/netmap", "a+")

        vale_name_bytes = bytes(vale_name) + b"\0" * (16 - len(vale_name))
        req = VALE_BPF_REQ(vale_name_bytes,
                           self.INSTALL_PROG,
                           4,
                           -1)
        fcntl.ioctl(f, self.NIOCCONFIG, req)

        f.close()
