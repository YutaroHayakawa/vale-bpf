#ifndef _VALE_BPF_NATIVE_H_
#define _VALE_BPF_NATIVE_H_

struct vale_bpf_native_req {
  uint8_t method;
  size_t len; // length of request data (below union)
  union {
    int ufd;
  };
};

enum vale_bpf_native_method { INSTALL_PROG, __MAX_METHOD=255 };

#endif
