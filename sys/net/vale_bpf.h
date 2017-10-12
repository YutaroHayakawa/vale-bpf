#ifndef _VALE_BPF_COMMON_H_
#define _VALE_BPF_COMMON_H_

#include <stdint.h>

struct vale_bpf_ctx {
  uint8_t *buf;
  uint16_t len;
  uint8_t *hint;
  uint8_t sport;
};

struct vale_bpf_md {
  uint32_t data;
  uint32_t data_end;
};

enum vale_bpf_action {
  VALE_BPF_DROP = 255,
  VALE_BPF_BROADCAST = 254
};

#endif
