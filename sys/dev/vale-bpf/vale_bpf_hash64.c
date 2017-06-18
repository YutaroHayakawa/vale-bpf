#include <linux/kernel.h>
#include <queue.h>
#include <vale_bpf_kern.h>
#include <vale_bpf_hash64.h>

#define mix(a, b, c)                                              \
do {                                                              \
  a -= b; a -= c; a ^= (c >> 13);                                 \
  b -= c; b -= a; b ^= (a << 8);                                  \
  c -= a; c -= b; c ^= (b >> 13);                                 \
  a -= b; a -= c; a ^= (c >> 12);                                 \
  b -= c; b -= a; b ^= (a << 16);                                 \
  c -= a; c -= b; c ^= (b >> 5);                                  \
  a -= b; a -= c; a ^= (c >> 3);                                  \
  b -= c; b -= a; b ^= (a << 10);                                 \
  c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static uint32_t get_hash(uint64_t key) {
  uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0;
  uint16_t *tmp = (uint16_t *)&key;

  b += (uint32_t)tmp[0];
  c += (uint32_t)tmp[1];
  a += (uint32_t)tmp[2];
  a += (uint32_t)tmp[3];

  mix(a, b, c);

  return (c & (VALE_BPF_HASH64_BUCKET_SIZE - 1));
}

int vale_bpf_hash64_init(struct vale_bpf_hash64 *h, uint16_t max_entry) {
  if (h == NULL || max_entry == 0) {
    return -1;
  }

  h->max_entry = max_entry;

  for (int i = 0; i < VALE_BPF_HASH64_BUCKET_SIZE; i++) {
    TAILQ_INIT(&(h->bucket[i]));
  }

  return 0;
}

int _vale_bpf_hash64_add_entry(struct vale_bpf_hash64 *h, uint64_t key, uint64_t val) {
  if (h == NULL || h->cur_entry == h->max_entry) {
    return -1;
  }

  struct vale_bpf_hash64_node *new;
  new = vale_bpf_os_malloc(sizeof(struct vale_bpf_hash64_node));
  if (new == NULL) {
    return -1;
  }

  new->key = key;
  new->val = val;

  TAILQ_INSERT_HEAD(&(h->bucket[get_hash(key)]), new, link);

  h->cur_entry++;

  printk("Added entry! key: %llu val: %llu\n", key, val);

  return 0;
}

int _vale_bpf_hash64_remove_entry(struct vale_bpf_hash64 *h, uint64_t key) {
  if (h == NULL || h->cur_entry == 0) {
    return -1;
  }

  struct vale_bpf_hash64_head *head = &(h->bucket[get_hash(key)]);

  struct vale_bpf_hash64_node *np;
  TAILQ_FOREACH(np, head, link) {
    if (np->key == key) {
      TAILQ_REMOVE(head, np, link);
      vale_bpf_os_free(np);
      h->cur_entry--;
      return 0;
    }
  }

  return 0;
}

/*
 * Current limitation
 *
 * This function returns UINT64_MAX when error occurs or found no entry.
 * So, you can't use UINT64_MAX as valid value.
 *
 */
uint64_t _vale_bpf_hash64_search_entry(struct vale_bpf_hash64 *h, uint64_t key) {
  if (h == NULL) {
    return -1;
  }

  struct vale_bpf_hash64_head *head = &(h->bucket[get_hash(key)]);

  struct vale_bpf_hash64_node *np;
  TAILQ_FOREACH(np, head, link) {
    if (np->key == key) {
      return np->val;
    }
  }

  return -1;
}

void vale_bpf_hash64_destroy(struct vale_bpf_hash64 *h) {
  if (h == NULL) {
    return;
  }

  struct vale_bpf_hash64_node *np;
  for (int i = 0; i < VALE_BPF_HASH64_BUCKET_SIZE; i++) {
    while(!TAILQ_EMPTY(&(h->bucket[i]))) {
      np = TAILQ_FIRST(&(h->bucket[i]));
      TAILQ_REMOVE(&(h->bucket[i]), np, link);
      printk("[%d] key: %llu val: %llu\n", i, np->key, np->val);
      vale_bpf_os_free(np);
    }
  }
}
