#include <vale_bpf.h>
#include <vale_bpf_ext_common.h>

#define memcpy(dst, src, size) __builtin_memcpy(dst, src, size)

struct tbl_ent {
  uint8_t addr[6];
  uint8_t port;
};

uint8_t rewrite_mac(uint8_t *buf, uint16_t len, uint8_t sport) {
  int err;
  uint64_t key = 0;
  uint64_t ent = 0;
  struct tbl_ent *entp = (struct tbl_ent *)&ent;

  memcpy(&key, buf + 6, 6); // use src mac as key

  ent = vale_bpf_hash64_search_entry(key);
  if ((uint64_t)ent == 18446744073709551615) {
    memcpy(entp->addr, buf + 6, 6);
    entp->port = sport;
    vale_bpf_hash64_add_entry(key, ent);
  }

  key = 0;
  memcpy(&key, buf, 6); // use dst mac as key

  ent = vale_bpf_hash64_search_entry(key);
  if (ent == 18446744073709551615) {
    return VALE_BPF_BROADCAST;
  } else {
    return entp->port;
  }
}
