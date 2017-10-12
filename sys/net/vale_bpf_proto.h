#ifndef _VALE_BPF_PROTO_H_
#define _VALE_BPF_PROTO_H_

#define VALE_BPF_MAX_PROG_LEN 1024 * 1024
#define MAX_METHOD 255

struct vale_bpf_req {
  uint8_t method;
  size_t len;
  union {
    struct vale_bpf_load_prog_data {
      int jit;
      void *code;
      size_t code_len;
    } prog_data;
  };
};

enum vale_bpf_method { LOAD_PROG };

struct vale_bpf_native_req {
  uint8_t method;
  size_t len; // length of request data (below union)
  union {
    int ufd;
  };
};

enum vale_bpf_native_method { INSTALL_PROG };

#endif
