#ifndef _VALE_BPF_H_
#define _VALE_BPF_H_

#include <stdint.h>

struct vale_bpf_ctx {
    uint8_t *buf;
    uint16_t len;
    uint8_t *hint;
    uint8_t sport;
};

enum {
  VALE_BPF_BROADCAST = 254,
  VALE_BPF_DROP = 255
};

#endif
