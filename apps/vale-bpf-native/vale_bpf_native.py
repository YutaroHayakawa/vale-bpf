from bcc import BPF
from ctypes import *
import fcntl
import ctypes
import os


_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2
_IOC_NRMASK = (1 << _IOC_NRBITS) - 1
_IOC_TYPEMASK = (1 << _IOC_TYPEBITS) - 1
_IOC_SIZEMASK = (1 << _IOC_SIZEBITS) - 1
_IOC_DIRMASK = (1 << _IOC_DIRBITS) - 1
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
IOC_NONE = 0
IOC_WRITE = 1
IOC_READ = 2


def IOC(dir, type, nr, size):
    assert dir <= _IOC_DIRMASK, dir
    assert type <= _IOC_TYPEMASK, type
    assert nr <= _IOC_NRMASK, nr
    assert size <= _IOC_SIZEMASK, size
    return (dir << _IOC_DIRSHIFT) | (type << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)


def IOC_TYPECHECK(t):
    result = ctypes.sizeof(t)
    assert result <= _IOC_SIZEMASK, result
    return result


def IO(type, nr):
    return IOC(IOC_NONE, type, nr, 0)


def IOR(type, nr, size):
    return IOC(IOC_READ, type, nr, IOC_TYPECHECK(size))


def IOW(type, nr, size):
    return IOC(IOC_WRITE, type, nr, IOC_TYPECHECK(size))


def IOWR(type, nr, size):
    return IOC(IOC_READ | IOC_WRITE, type, nr, IOC_TYPECHECK(size))


def IOC_DIR(nr):
    return (nr >> _IOC_DIRSHIFT) & _IOC_DIRMASK


def IOC_TYPE(nr):
    return (nr >> _IOC_TYPESHIFT) & _IOC_TYPEMASK


def IOC_NR(nr):
    return (nr >> _IOC_NRSHIFT) & _IOC_NRMASK


def IOC_SIZE(nr):
    return (nr >> _IOC_SIZESHIFT) & _IOC_SIZEMASK


IOC_IN = IOC_WRITE << _IOC_DIRSHIFT
IOC_OUT = IOC_READ << _IOC_DIRSHIFT
IOC_INOUT = (IOC_WRITE | IOC_READ) << _IOC_DIRSHIFT
IOCSIZE_MASK = _IOC_SIZEMASK << _IOC_SIZESHIFT
IOCSIZE_SHIFT = _IOC_SIZESHIFT


class NM_IFREQ(Structure):
    _fields_ = [
        ('nifr_name', c_char * 16),
        ('data', c_char * 256)
    ]


class VALE_BPF_NATIVE_INSTALL_REQ(Structure):
    _fields_ = [
        ('prog_fd', c_int),
        ('meta_map_fd', c_int)
    ]


class VALE_BPF_NATIVE_REQ(Structure):
    _fields_ = [
        ('vale_name', c_char * 16),
        ('method', c_uint8),
        ('len', c_size_t),
        ('install_req', VALE_BPF_NATIVE_INSTALL_REQ),
        ('_pad', c_char * (256 - 17))
    ]


class VALE_BPF_NATIVE(BPF):

    INSTALL_PROG=0
    UNINSTALL_PROG=1
    VALE_BPF_NATIVE = BPF.XDP
    NIOCCONFIG = IOWR(ord('i'), 150, NM_IFREQ)

    def __init__(self, src_file='', hdr_file='',
            text=None, cb=None, debug=0, cflags=[],
            usdt_contexts=[]):

        super(VALE_BPF_NATIVE, self).__init__(src_file, hdr_file,
                text, cb, debug, cflags, usdt_contexts)

    def attach_vale_bpf_native(self, vale_name, func_name):
        func = self.load_func(func_name, self.VALE_BPF_NATIVE)

        try:
            tbl = self.get_table("meta_map")
        except:
            print "Failed to get meta_map. Did you defined meta_map in your program?"

        vale_name_bytes = bytes(vale_name) + b"\0" * (16 - len(vale_name))

        inst_req = VALE_BPF_NATIVE_INSTALL_REQ(func.fd, tbl.map_fd)

        req = VALE_BPF_NATIVE_REQ(vale_name_bytes,
                                  self.INSTALL_PROG,
                                  8,
                                  inst_req)

        f = open("/dev/netmap", "a+")
        fcntl.ioctl(f, self.NIOCCONFIG, req)

        f.close()

    def remove_vale_bpf_native(self, vale_name):
        f = open("/dev/netmap", "a+")

        vale_name_bytes = bytes(vale_name) + b"\0" * (16 - len(vale_name))
        req = VALE_BPF_NATIVE_REQ(vale_name_bytes,
                                  self.UNINSTALL_PROG)
        fcntl.ioctl(f, self.NIOCCONFIG, req)

        f.close()
