/* This file is for eBPF targeted C code */
#ifndef _VALE_BPF_EXT_COMMON_H_
#define _VALE_BPF_EXT_COMMON_H_

#include <stdint.h>

/* declare external functions for eBPF VM */
extern void set_pkt_len(uint16_t len);
extern uint64_t vale_bpf_hash64_add_entry(uint64_t key, uint64_t val);
extern int vale_bpf_hash64_remove_entry(uint64_t key);
extern uint64_t vale_bpf_hash64_search_entry(uint64_t key);

#endif
