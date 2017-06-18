#ifndef _VALE_BPF_HASH64_H_
#define _VALE_BPF_HASH64_H_

#include <vale_bpf_kern.h>
#include <queue.h>

#define VALE_BPF_HASH64_BUCKET_SIZE 1024

struct vale_bpf_hash64_node {
  TAILQ_ENTRY(vale_bpf_hash64_node) link;
  uint64_t key;
  uint64_t val;
};

TAILQ_HEAD(vale_bpf_hash64_head, vale_bpf_hash64_node);

struct vale_bpf_hash64 {
  struct vale_bpf_hash64_head bucket[VALE_BPF_HASH64_BUCKET_SIZE];
  uint16_t max_entry;
  uint16_t cur_entry;
};

extern int vale_bpf_hash64_init(struct vale_bpf_hash64 *h, uint16_t max_entry);
extern int _vale_bpf_hash64_add_entry(struct vale_bpf_hash64 *h, uint64_t key, uint64_t val);
extern int _vale_bpf_hash64_remove_entry(struct vale_bpf_hash64 *h, uint64_t key);
extern uint64_t _vale_bpf_hash64_search_entry(struct vale_bpf_hash64 *h, uint64_t key);
extern void vale_bpf_hash64_destroy(struct vale_bpf_hash64 *h);

#endif
