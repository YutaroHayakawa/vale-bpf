#ifndef _VALE_BPF_H_
#define _VALE_BPF_H_

#define VALE_BPF_MAX_PROG_LEN 1024 * 1024

struct vale_bpf_req {
  uint8_t method;
  size_t len;
  void *data;
};

enum vale_bpf_method {
  LOAD_PROG,
  __MAX_METHOD
};

#endif
