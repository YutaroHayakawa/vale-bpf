/* This file is for eBPF targeted C code */
#ifndef _VALE_BPF_EXT_COMMON_H_
#define _VALE_BPF_EXT_COMMON_H_

#include <stdint.h>

/* declare external functions for eBPF VM */
extern uint16_t get_pkt_len(void);
extern void set_pkt_len(uint16_t);
extern uint8_t get_src_port(void);

#endif
