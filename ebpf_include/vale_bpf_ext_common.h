/* This file is for eBPF targeted C code */
#ifndef _VALE_BPF_EXT_COMMON_H_
#define _VALE_BPF_EXT_COMMON_H_

#include <stdint.h>

/* declare external functions for eBPF VM */
extern void set_pkt_len(uint16_t);

#endif
