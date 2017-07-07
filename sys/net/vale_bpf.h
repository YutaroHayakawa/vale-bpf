#ifndef _VALE_BPF_H_
#define _VALE_BPF_H_

#define VALE_BPF_MAX_PROG_LEN 1024 * 1024

struct vale_bpf_req {
  uint8_t method;
  size_t len;
  union {
    struct vale_bpf_load_prog_data {
      uint8_t id;
      int jit;
      void *code;
      size_t code_len;
    } prog_data;
    struct vale_bpf_reg_data {
      uint8_t id;
    } reg_data;
  };
};

enum vale_bpf_method { REGISTER_VM, LOAD_PROG, UNREGISTER_VM, __MAX_METHOD };

#endif
