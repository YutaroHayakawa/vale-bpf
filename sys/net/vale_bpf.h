#ifndef _VALE_BPF_H_
#define _VALE_BPF_H_

#include <net/vale_bpf_common.h>

struct vale_bpf_ctx {
  uint8_t *buf;
  uint16_t len;
  uint8_t *hint;
  uint8_t sport;
};

#endif
